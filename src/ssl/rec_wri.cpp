/*
* TLS Record Writing
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/handshake_hash.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>
#include <botan/libstate.h>

namespace Botan {

/**
* Record_Writer Constructor
*/
Record_Writer::Record_Writer(Socket& sock) :
   socket(sock), buffer(DEFAULT_BUFFERSIZE)
   {
   reset();
   }

/**
* Reset the state
*/
void Record_Writer::reset()
   {
   cipher.reset();
   mac.reset();

   buffer.clear();
   buf_pos = 0;

   major = minor = buf_type = 0;
   block_size = 0;
   mac_size = 0;
   iv_size = 0;

   seq_no = 0;
   }

/**
* Set the version to use
*/
void Record_Writer::set_version(Version_Code version)
   {
   if(version != SSL_V3 && version != TLS_V10 && version != TLS_V11)
      throw Invalid_Argument("Record_Writer: Invalid protocol version");

   major = (version >> 8) & 0xFF;
   minor = (version & 0xFF);
   }

/**
* Set the keys for writing
*/
void Record_Writer::set_keys(const CipherSuite& suite, const SessionKeys& keys,
                             Connection_Side side)
   {
   cipher.reset();
   mac.reset();

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
      if(major == 3 && minor == 0)
         mac.append(new MAC_Filter("SSL3-MAC(" + mac_algo + ")", mac_key));
      else
         mac.append(new MAC_Filter("HMAC(" + mac_algo + ")", mac_key));

      mac_size = output_length_of(mac_algo);
      }
   else
      throw Invalid_Argument("Record_Writer: Unknown hash " + mac_algo);
   }

/**
* Send one or more records to the other side
*/
void Record_Writer::send(byte type, byte input)
   {
   send(type, &input, 1);
   }

/**
* Send one or more records to the other side
*/
void Record_Writer::send(byte type, const byte input[], u32bit length)
   {
   if(type != buf_type)
      flush();

   const u32bit BUFFER_SIZE = buffer.size();
   buf_type = type;

   // FIXME: compression right here

   buffer.copy(buf_pos, input, length);
   if(buf_pos + length >= BUFFER_SIZE)
      {
      send_record(buf_type, buffer, length);
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

/**
* Split buffer into records, and send them all
*/
void Record_Writer::flush()
   {
   const byte* buf_ptr = buffer.begin();
   u32bit offset = 0;

   while(offset != buf_pos)
      {
      u32bit record_size = buf_pos - offset;
      if(record_size > MAX_PLAINTEXT_SIZE)
         record_size = MAX_PLAINTEXT_SIZE;

      send_record(buf_type, buf_ptr + offset, record_size);
      offset += record_size;
      }
   buf_type = 0;
   buf_pos = 0;
   }

/**
* Encrypt and send the record
*/
void Record_Writer::send_record(byte type, const byte buf[], u32bit length)
   {
   if(length >= MAX_COMPRESSED_SIZE)
      throw TLS_Exception(INTERNAL_ERROR,
                          "Record_Writer: Compressed packet is too big");

   if(mac_size == 0)
      send_record(type, major, minor, buf, length);
   else
      {
      mac.start_msg();
      for(u32bit j = 0; j != 8; j++)
         mac.write(get_byte(j, seq_no));
      mac.write(type);

      if(major > 3 || (major == 3 && minor != 0))
         {
         mac.write(major);
         mac.write(minor);
         }

      mac.write(get_byte(2, length));
      mac.write(get_byte(3, length));
      mac.write(buf, length);
      mac.end_msg();

      // TODO: This could all use a single buffer

      SecureVector<byte> buf_mac = mac.read_all(Pipe::LAST_MESSAGE);

      cipher.start_msg();

      if(iv_size)
         {
         RandomNumberGenerator& rng = global_state().global_rng();

         SecureVector<byte> random_iv(iv_size);

         rng.randomize(&random_iv[0], random_iv.size());

         cipher.write(random_iv);
         }

      cipher.write(buf, length);
      cipher.write(buf_mac);

      if(block_size)
         {
         u32bit pad_val =
            (block_size - (1 + length + buf_mac.size())) % block_size;

         for(u32bit j = 0; j != pad_val + 1; j++)
            cipher.write(pad_val);
         }
      cipher.end_msg();

      SecureVector<byte> output = cipher.read_all(Pipe::LAST_MESSAGE);

      send_record(type, major, minor, output, output.size());

      seq_no++;
      }
   }

/**
* Send a final record packet
*/
void Record_Writer::send_record(byte type, byte major, byte minor,
                                const byte out[], u32bit length)
   {
   if(length >= MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(INTERNAL_ERROR,
                          "Record_Writer: Record is too big");

   byte header[5] = { type, major, minor, 0 };
   for(u32bit j = 0; j != 2; j++)
      header[j+3] = get_byte<u16bit>(j, length);

   socket.write(header, 5);
   socket.write(out, length);
   }

/**
* Send an alert
*/
void Record_Writer::alert(Alert_Level level, Alert_Type type)
   {
   byte alert[2] = { (byte)level, (byte)type };
   send(ALERT, alert, sizeof(alert));
   flush();
   }

}
