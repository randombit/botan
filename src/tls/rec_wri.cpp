/*
* TLS Record Writing
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/lookup.h>
#include <botan/internal/rounding.h>
#include <botan/internal/assert.h>
#include <botan/loadstor.h>
#include <botan/libstate.h>

namespace Botan {

/*
* Record_Writer Constructor
*/
Record_Writer::Record_Writer(std::tr1::function<void (const byte[], size_t)> out,
                             size_t max_fragment) :
   output_fn(out),
   buffer(max_fragment ? max_fragment : static_cast<size_t>(MAX_PLAINTEXT_SIZE))
   {
   mac = 0;
   reset();
   }

/*
* Reset the state
*/
void Record_Writer::reset()
   {
   cipher.reset();

   delete mac;
   mac = 0;

   zeroise(buffer);
   buf_pos = 0;

   major = minor = buf_type = 0;
   block_size = 0;
   mac_size = 0;
   iv_size = 0;

   seq_no = 0;
   }

/*
* Set the version to use
*/
void Record_Writer::set_version(Version_Code version)
   {
   if(version != SSL_V3 && version != TLS_V10 && version != TLS_V11)
      throw Invalid_Argument("Record_Writer: Invalid protocol version");

   major = (version >> 8) & 0xFF;
   minor = (version & 0xFF);
   }

/*
* Set the keys for writing
*/
void Record_Writer::set_keys(const CipherSuite& suite,
                             const SessionKeys& keys,
                             Connection_Side side)
   {
   cipher.reset();
   delete mac;
   mac = 0;

   SymmetricKey mac_key, cipher_key;
   InitializationVector iv;

   if(side == CLIENT)
      {
      cipher_key = keys.client_cipher_key();
      iv = keys.client_iv();
      mac_key = keys.client_mac_key();
      }
   else
      {
      cipher_key = keys.server_cipher_key();
      iv = keys.server_iv();
      mac_key = keys.server_mac_key();
      }

   const std::string cipher_algo = suite.cipher_algo();
   const std::string mac_algo = suite.mac_algo();

   if(have_block_cipher(cipher_algo))
      {
      cipher.append(get_cipher(
                       cipher_algo + "/CBC/NoPadding",
                       cipher_key, iv, ENCRYPTION)
         );
      block_size = block_size_of(cipher_algo);

      if(major > 3 || (major == 3 && minor >= 2))
         iv_size = block_size;
      else
         iv_size = 0;
      }
   else if(have_stream_cipher(cipher_algo))
      {
      cipher.append(get_cipher(cipher_algo, cipher_key, ENCRYPTION));
      block_size = 0;
      iv_size = 0;
      }
   else
      throw Invalid_Argument("Record_Writer: Unknown cipher " + cipher_algo);

   if(have_hash(mac_algo))
      {
      Algorithm_Factory& af = global_state().algorithm_factory();

      if(major == 3 && minor == 0)
         mac = af.make_mac("SSL3-MAC(" + mac_algo + ")");
      else
         mac = af.make_mac("HMAC(" + mac_algo + ")");

      mac->set_key(mac_key);
      mac_size = mac->output_length();
      }
   else
      throw Invalid_Argument("Record_Writer: Unknown hash " + mac_algo);
   }

/*
* Send one or more records to the other side
*/
void Record_Writer::send(byte type, const byte input[], size_t length)
   {
   if(type != buf_type)
      flush();

   const size_t BUFFER_SIZE = buffer.size();
   buf_type = type;

   // FIXME: compression right here

   buffer.copy(buf_pos, input, length);
   if(buf_pos + length >= BUFFER_SIZE)
      {
      send_record(buf_type, &buffer[0], length);
      input += (BUFFER_SIZE - buf_pos);
      length -= (BUFFER_SIZE - buf_pos);
      while(length >= BUFFER_SIZE)
         {
         send_record(buf_type, input, BUFFER_SIZE);
         input += BUFFER_SIZE;
         length -= BUFFER_SIZE;
         }
      buffer.copy(input, length);
      buf_pos = 0;
      }
   buf_pos += length;
   }

/*
* Split buffer into records, and send them all
*/
void Record_Writer::flush()
   {
   const byte* buf_ptr = &buffer[0];
   size_t offset = 0;

   while(offset != buf_pos)
      {
      size_t record_size = buf_pos - offset;
      if(record_size > MAX_PLAINTEXT_SIZE)
         record_size = MAX_PLAINTEXT_SIZE;

      send_record(buf_type, buf_ptr + offset, record_size);
      offset += record_size;
      }
   buf_type = 0;
   buf_pos = 0;
   }

/*
* Encrypt and send the record
*/
void Record_Writer::send_record(byte type, const byte input[], size_t length)
   {
   if(length >= MAX_COMPRESSED_SIZE)
      throw TLS_Exception(INTERNAL_ERROR,
                          "Record_Writer: Compressed packet is too big");

   if(mac_size == 0)
      {
      if(length >= MAX_CIPHERTEXT_SIZE)
         throw TLS_Exception(INTERNAL_ERROR,
                             "Record_Writer: Record is too big");

      const byte header[5] = {
         type,
         major,
         minor,
         get_byte<u16bit>(0, length),
         get_byte<u16bit>(1, length)
      };

      output_fn(header, 5);
      output_fn(input, length);
      }
   else
      {
      mac->update_be(seq_no);
      mac->update(type);

      if(major > 3 || (major == 3 && minor != 0))
         {
         mac->update(major);
         mac->update(minor);
         }

      mac->update(get_byte<u16bit>(0, length));
      mac->update(get_byte<u16bit>(1, length));
      mac->update(input, length);

      const size_t buf_size = round_up(iv_size + length +
                                       mac->output_length() + 1,
                                       block_size);

      if(buf_size >= MAX_CIPHERTEXT_SIZE)
         throw TLS_Exception(INTERNAL_ERROR,
                             "Record_Writer: Record is too big");

      MemoryVector<byte> buf(5 + buf_size);

      // TLS record header
      buf[0] = type;
      buf[1] = major;
      buf[2] = minor;
      buf[3] = get_byte<u16bit>(0, buf_size);
      buf[4] = get_byte<u16bit>(1, buf_size);

      byte* buf_write_ptr = &buf[5];

      if(iv_size)
         {
         RandomNumberGenerator& rng = global_state().global_rng();
         rng.randomize(buf_write_ptr, iv_size);
         buf_write_ptr += iv_size;
         }

      copy_mem(buf_write_ptr, input, length);
      buf_write_ptr += length;

      mac->final(buf_write_ptr);
      buf_write_ptr += mac->output_length();

      if(block_size)
         {
         const size_t pad_val =
            buf_size - (iv_size + length + mac->output_length() + 1);

         for(size_t i = 0; i != pad_val + 1; ++i)
            {
            *buf_write_ptr = pad_val;
            buf_write_ptr += 1;
            }
         }

      // FIXME: this could be done in-place without copying
      cipher.process_msg(&buf[5], buf.size() - 5);
      size_t got_back = cipher.read(&buf[5], buf.size() - 5, Pipe::LAST_MESSAGE);
      BOTAN_ASSERT_EQUAL(got_back, buf.size()-5, "CBC didn't encrypt full blocks");

      output_fn(&buf[0], buf.size());

      seq_no++;
      }
   }

/*
* Send an alert
*/
void Record_Writer::alert(Alert_Level level, Alert_Type type)
   {
   byte alert[2] = { level, type };
   send(ALERT, alert, sizeof(alert));
   flush();
   }

}
