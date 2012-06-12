/*
* TLS Record Reading
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* Reset the state
*/
void Record_Reader::reset()
   {
   cipher.reset();

   delete mac;
   mac = 0;

   mac_size = 0;
   block_size = 0;
   iv_size = 0;
   major = minor = 0;
   seq_no = 0;
   }

/*
* Set the version to use
*/
void Record_Reader::set_version(Version_Code version)
   {
   if(version != SSL_V3 && version != TLS_V10 && version != TLS_V11)
      throw Invalid_Argument("Record_Reader: Invalid protocol version");

   major = (version >> 8) & 0xFF;
   minor = (version & 0xFF);
   }

/*
* Set the keys for reading
*/
void Record_Reader::set_keys(const CipherSuite& suite, const SessionKeys& keys,
                             Connection_Side side)
   {
   cipher.reset();
   delete mac;
   mac = 0;
   seq_no = 0;

   SymmetricKey mac_key, cipher_key;
   InitializationVector iv;

   if(side == CLIENT)
      {
      cipher_key = keys.server_cipher_key();
      iv = keys.server_iv();
      mac_key = keys.server_mac_key();
      }
   else
      {
      cipher_key = keys.client_cipher_key();
      iv = keys.client_iv();
      mac_key = keys.client_mac_key();
      }

   const std::string cipher_algo = suite.cipher_algo();
   const std::string mac_algo = suite.mac_algo();

   if(have_block_cipher(cipher_algo))
      {
      cipher.append(get_cipher(
                       cipher_algo + "/CBC/NoPadding",
                       cipher_key, iv, DECRYPTION)
         );
      block_size = block_size_of(cipher_algo);

      if(major > 3 || (major == 3 && minor >= 2))
         iv_size = block_size;
      else
         iv_size = 0;
      }
   else if(have_stream_cipher(cipher_algo))
      {
      cipher.append(get_cipher(cipher_algo, cipher_key, DECRYPTION));
      block_size = 0;
      iv_size = 0;
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown cipher " + cipher_algo);

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
      throw Invalid_Argument("Record_Reader: Unknown hash " + mac_algo);
   }

void Record_Reader::add_input(const byte input[], size_t input_size)
   {
   input_queue.write(input, input_size);
   }

/*
* Retrieve the next record
*/
size_t Record_Reader::get_record(byte& msg_type,
                                 MemoryRegion<byte>& output)
   {
   byte header[5] = { 0 };

   const size_t have_in_queue = input_queue.size();

   if(have_in_queue < sizeof(header))
      return (sizeof(header) - have_in_queue);

   /*
   * We peek first to make sure we have the full record
   */
   input_queue.peek(header, sizeof(header));

   // SSLv2-format client hello?
   if(header[0] & 0x80 && header[2] == 1 && header[3] == 3)
      {
      size_t record_len = make_u16bit(header[0], header[1]) & 0x7FFF;

      if(have_in_queue < record_len + 2)
         return (record_len + 2 - have_in_queue);

      msg_type = HANDSHAKE;
      output.resize(record_len + 4);

      input_queue.read(&output[2], record_len + 2);
      output[0] = CLIENT_HELLO_SSLV2;
      output[1] = 0;
      output[2] = header[0] & 0x7F;
      output[3] = header[1];

      return 0;
      }

   if(header[0] != CHANGE_CIPHER_SPEC &&
      header[0] != ALERT &&
      header[0] != HANDSHAKE &&
      header[0] != APPLICATION_DATA)
      {
      throw TLS_Exception(UNEXPECTED_MESSAGE,
                          "Record_Reader: Unknown record type");
      }

   const u16bit version    = make_u16bit(header[1], header[2]);
   const u16bit record_len = make_u16bit(header[3], header[4]);

   if(major && (header[1] != major || header[2] != minor))
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Record_Reader: Got unexpected version");

   // If insufficient data, return without doing anything
   if(have_in_queue < (sizeof(header) + record_len))
      return (sizeof(header) + record_len - have_in_queue);

   SecureVector<byte> buffer(record_len);

   input_queue.read(header, sizeof(header)); // pull off the header
   input_queue.read(&buffer[0], buffer.size());

   /*
   * We are handshaking, no crypto to do so return as-is
   * TODO: Check msg_type to confirm a handshake?
   */
   if(mac_size == 0)
      {
      msg_type = header[0];
      output = buffer;
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext

   cipher.process_msg(buffer);
   SecureVector<byte> plaintext = cipher.read_all(Pipe::LAST_MESSAGE);

   size_t pad_size = 0;

   if(block_size)
      {
      byte pad_value = plaintext[plaintext.size()-1];
      pad_size = pad_value + 1;

      /*
      * Check the padding; if it is wrong, then say we have 0 bytes of
      * padding, which should ensure that the MAC check below does not
      * suceed. This hides a timing channel.
      *
      * This particular countermeasure is recommended in the TLS 1.2
      * spec (RFC 5246) in section 6.2.3.2
      */
      if(version == SSL_V3)
         {
         if(pad_value > block_size)
            pad_size = 0;
         }
      else
         {
         bool padding_good = true;

         for(size_t i = 0; i != pad_size; ++i)
            if(plaintext[plaintext.size()-i-1] != pad_value)
               padding_good = false;

         if(!padding_good)
            pad_size = 0;
         }
      }

   if(plaintext.size() < mac_size + pad_size + iv_size)
      throw Decoding_Error("Record_Reader: Record truncated");

   const size_t mac_offset = plaintext.size() - (mac_size + pad_size);
   SecureVector<byte> received_mac(&plaintext[mac_offset],
                                   mac_size);

   const u16bit plain_length = plaintext.size() - (mac_size + pad_size + iv_size);

   mac->update_be(seq_no);
   mac->update(header[0]); // msg_type

   if(version != SSL_V3)
      for(size_t i = 0; i != 2; ++i)
         mac->update(get_byte(i, version));

   mac->update_be(plain_length);
   mac->update(&plaintext[iv_size], plain_length);

   ++seq_no;

   SecureVector<byte> computed_mac = mac->final();

   if(received_mac != computed_mac)
      throw TLS_Exception(BAD_RECORD_MAC, "Record_Reader: MAC failure");

   msg_type = header[0];

   output.resize(plain_length);
   copy_mem(&output[0], &plaintext[iv_size], plain_length);
   return 0;
   }

}
