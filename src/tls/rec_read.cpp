/*
* TLS Record Reading
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/rounding.h>
#include <botan/internal/assert.h>

namespace Botan {

Record_Reader::Record_Reader()
   {
   m_mac = 0;
   reset();
   set_maximum_fragment_size(0);
   }

/*
* Reset the state
*/
void Record_Reader::reset()
   {
   m_cipher.reset();

   delete m_mac;
   m_mac = 0;

   m_mac_size = 0;
   m_block_size = 0;
   m_iv_size = 0;
   m_major = m_minor = 0;
   m_seq_no = 0;
   set_maximum_fragment_size(0);
   }

void Record_Reader::set_maximum_fragment_size(size_t max_fragment)
   {
   if(max_fragment == 0)
      m_max_fragment = MAX_PLAINTEXT_SIZE;
   else
      m_max_fragment = clamp(max_fragment, 128, MAX_PLAINTEXT_SIZE);
   }

/*
* Set the version to use
*/
void Record_Reader::set_version(Version_Code version)
   {
   if(version != SSL_V3 && version != TLS_V10 && version != TLS_V11)
      throw Invalid_Argument("Record_Reader: Invalid protocol version");

   m_major = (version >> 8) & 0xFF;
   m_minor = (version & 0xFF);
   }

/*
* Get the version in use
*/
Version_Code Record_Reader::get_version() const
   {
   return static_cast<Version_Code>(
      (static_cast<u16bit>(m_major) << 8) | m_minor);
   }

/*
* Set the keys for reading
*/
void Record_Reader::activate(const TLS_Cipher_Suite& suite,
                             const SessionKeys& keys,
                             Connection_Side side)
   {
   m_cipher.reset();
   delete m_mac;
   m_mac = 0;
   m_seq_no = 0;

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
      m_cipher.append(get_cipher(
                       cipher_algo + "/CBC/NoPadding",
                       cipher_key, iv, DECRYPTION)
         );
      m_block_size = block_size_of(cipher_algo);

      if(m_major > 3 || (m_major == 3 && m_minor >= 2))
         m_iv_size = m_block_size;
      else
         m_iv_size = 0;
      }
   else if(have_stream_cipher(cipher_algo))
      {
      m_cipher.append(get_cipher(cipher_algo, cipher_key, DECRYPTION));
      m_block_size = 0;
      m_iv_size = 0;
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown cipher " + cipher_algo);

   if(have_hash(mac_algo))
      {
      Algorithm_Factory& af = global_state().algorithm_factory();

      if(m_major == 3 && m_minor == 0)
         m_mac = af.make_mac("SSL3-MAC(" + mac_algo + ")");
      else
         m_mac = af.make_mac("HMAC(" + mac_algo + ")");

      m_mac->set_key(mac_key);
      m_mac_size = m_mac->output_length();
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown hash " + mac_algo);
   }

void Record_Reader::add_input(const byte input[], size_t input_size)
   {
   m_input_queue.write(input, input_size);
   }

/*
* Retrieve the next record
*/
size_t Record_Reader::get_record(byte& msg_type,
                                 MemoryVector<byte>& output)
   {
   byte header[5] = { 0 };

   const size_t have_in_queue = m_input_queue.size();

   if(have_in_queue < sizeof(header))
      return (sizeof(header) - have_in_queue);

   /*
   * We peek first to make sure we have the full record
   */
   m_input_queue.peek(header, sizeof(header));

   // SSLv2-format client hello?
   if(header[0] & 0x80 && header[2] == 1 && header[3] == 3)
      {
      size_t record_len = make_u16bit(header[0], header[1]) & 0x7FFF;

      if(have_in_queue < record_len + 2)
         return (record_len + 2 - have_in_queue);

      msg_type = HANDSHAKE;
      output.resize(record_len + 4);

      m_input_queue.read(&output[2], record_len + 2);
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

   if(m_major && (header[1] != m_major || header[2] != m_minor))
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Record_Reader: Got unexpected version");

   if(record_len > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(RECORD_OVERFLOW,
                          "Got message that exceeds maximum size");

   // If insufficient data, return without doing anything
   if(have_in_queue < (sizeof(header) + record_len))
      return (sizeof(header) + record_len - have_in_queue);

   m_readbuf.resize(record_len);

   m_input_queue.read(header, sizeof(header)); // pull off the header
   m_input_queue.read(&m_readbuf[0], m_readbuf.size());

   // Null mac means no encryption either, only valid during handshake
   if(m_mac_size == 0)
      {
      if(header[0] != CHANGE_CIPHER_SPEC &&
         header[0] != ALERT &&
         header[0] != HANDSHAKE)
         {
         throw TLS_Exception(DECODE_ERROR, "Invalid msg type received during handshake");
         }

      msg_type = header[0];
      std::swap(output, m_readbuf); // move semantics
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext

   // FIXME: process in-place
   m_cipher.process_msg(m_readbuf);
   size_t got_back = m_cipher.read(&m_readbuf[0], m_readbuf.size(), Pipe::LAST_MESSAGE);
   BOTAN_ASSERT_EQUAL(got_back, m_readbuf.size(), "Cipher didn't decrypt full amount");

   size_t pad_size = 0;

   if(m_block_size)
      {
      byte pad_value = m_readbuf[m_readbuf.size()-1];
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
         if(pad_value > m_block_size)
            pad_size = 0;
         }
      else
         {
         bool padding_good = true;

         for(size_t i = 0; i != pad_size; ++i)
            if(m_readbuf[m_readbuf.size()-i-1] != pad_value)
               padding_good = false;

         if(!padding_good)
            pad_size = 0;
         }
      }

   if(m_readbuf.size() < m_mac_size + pad_size + m_iv_size)
      throw Decoding_Error("Record_Reader: Record truncated");

   const u16bit plain_length = m_readbuf.size() - (m_mac_size + pad_size + m_iv_size);

   if(plain_length > m_max_fragment)
      throw TLS_Exception(RECORD_OVERFLOW, "Plaintext record is too large");

   m_mac->update_be(m_seq_no);
   m_mac->update(header[0]); // msg_type

   if(version != SSL_V3)
      for(size_t i = 0; i != 2; ++i)
         m_mac->update(get_byte(i, version));

   m_mac->update_be(plain_length);
   m_mac->update(&m_readbuf[m_iv_size], plain_length);

   ++m_seq_no;

   MemoryVector<byte> computed_mac = m_mac->final();

   const size_t mac_offset = m_readbuf.size() - (m_mac_size + pad_size);

   if(computed_mac.size() != m_mac_size)
      throw TLS_Exception(INTERNAL_ERROR,
                          "MAC produced value of unexpected size");

   if(!same_mem(&m_readbuf[mac_offset], &computed_mac[0], m_mac_size))
      throw TLS_Exception(BAD_RECORD_MAC, "Record_Reader: MAC failure");

   msg_type = header[0];

   output.resize(plain_length);
   copy_mem(&output[0], &m_readbuf[m_iv_size], plain_length);
   return 0;
   }

}
