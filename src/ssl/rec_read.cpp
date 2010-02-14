/**
* TLS Record Reading Source File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/tls_exceptn.h>
#include <botan/loadstor.h>
#include <botan/lookup.h>

namespace Botan {

/**
* Record_Reader Constructor
*/
Record_Reader::Record_Reader(Socket& sock) : socket(sock)
   {
   reset();
   }

/**
* Reset the state
*/
void Record_Reader::reset()
   {
   compress.reset();
   cipher.reset();
   mac.reset();
   do_compress = false;
   mac_size = pad_amount = 0;
   major = minor = 0;
   seq_no = 0;
   }

/**
* Set the version to use
*/
void Record_Reader::set_version(Version_Code version)
   {
   if(version != SSL_V3 && version != TLS_V10)
      throw Invalid_Argument("Record_Reader: Invalid protocol version");

   major = (version >> 8) & 0xFF;
   minor = (version & 0xFF);
   }

/**
* Set the compression algorithm
*/
void Record_Reader::set_compressor(Filter* compressor)
   {
   compress.append(compressor);
   do_compress = true;
   }

/**
* Set the keys for reading
*/
void Record_Reader::set_keys(const CipherSuite& suite, const SessionKeys& keys,
                             Connection_Side side)
   {
   cipher.reset();
   mac.reset();

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
      pad_amount = block_size_of(cipher_algo);
      }
   else if(have_stream_cipher(cipher_algo))
      {
      cipher.append(get_cipher(cipher_algo, cipher_key, DECRYPTION));
      pad_amount = 0;
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown cipher " + cipher_algo);

   if(have_hash(mac_algo))
      {
      if(major == 3 && minor == 0)
         mac.append(new MAC_Filter("SSL3-MAC(" + mac_algo + ")", mac_key));
      else
         mac.append(new MAC_Filter("HMAC(" + mac_algo + ")", mac_key));

      mac_size = output_length_of(mac_algo);
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown hash " + mac_algo);
   }

/**
* Retrieve the next record
*/
SecureVector<byte> Record_Reader::get_record(byte& msg_type)
   {
   byte header[5] = { 0 };

   u32bit got = socket.read(header, sizeof(header));

   if(got == 0)
      {
      msg_type = CONNECTION_CLOSED;
      return SecureVector<byte>();
      }
   else if(got != sizeof(header))
      throw Decoding_Error("Record_Reader: Record truncated");

   msg_type = header[0];

   const u16bit version = make_u16bit(header[1], header[2]);

   if(major && (header[1] != major || header[2] != minor))
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Record_Reader: Got unexpected version");

   SecureVector<byte> buffer(make_u16bit(header[3], header[4]));
   if(socket.read(buffer, buffer.size()) != buffer.size())
      throw Decoding_Error("Record_Reader: Record truncated");

   if(mac_size == 0)
      return buffer;

   cipher.process_msg(buffer);
   SecureVector<byte> plaintext = cipher.read_all(Pipe::LAST_MESSAGE);

   u32bit pad_size = 0;
   if(pad_amount)
      {
      byte pad_value = plaintext[plaintext.size()-1];
      pad_size = pad_value + 1;

      if(version == SSL_V3)
         {
         if(pad_value > pad_amount)
            throw TLS_Exception(BAD_RECORD_MAC,
                                "Record_Reader: Bad padding");
         }
      else
         {
         for(u32bit j = 0; j != pad_size; j++)
            if(plaintext[plaintext.size()-j-1] != pad_value)
               throw TLS_Exception(BAD_RECORD_MAC,
                                   "Record_Reader: Bad padding");
         }
      }

   if(plaintext.size() < mac_size + pad_size)
      throw Decoding_Error("Record_Reader: Record truncated");

   const u32bit mac_offset = plaintext.size() - (mac_size + pad_size);
   SecureVector<byte> recieved_mac(plaintext.begin() + mac_offset,
                                   mac_size);

   const u16bit plain_length = plaintext.size() - (mac_size + pad_size);

   mac.start_msg();
   for(u32bit j = 0; j != 8; j++)
      mac.write(get_byte(j, seq_no));
   mac.write(msg_type);

   if(version != SSL_V3)
      for(u32bit j = 0; j != 2; j++)
         mac.write(get_byte(j, version));

   for(u32bit j = 0; j != 2; j++)
      mac.write(get_byte(j, plain_length));
   mac.write(plaintext, plain_length);
   mac.end_msg();

   seq_no++;

   SecureVector<byte> computed_mac = mac.read_all(Pipe::LAST_MESSAGE);

   if(recieved_mac != computed_mac)
      throw TLS_Exception(BAD_RECORD_MAC, "Record_Reader: MAC failure");

   return SecureVector<byte>(plaintext, mac_offset);
   }

}
