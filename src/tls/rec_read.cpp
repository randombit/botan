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

   // A single record is never larger than this
   m_readbuf.resize(MAX_CIPHERTEXT_SIZE);
   }

/*
* Reset the state
*/
void Record_Reader::reset()
   {
   m_cipher.reset();

   delete m_mac;
   m_mac = 0;

   zeroise(m_readbuf);
   m_readbuf_pos = 0;

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

void Record_Reader::consume_input(const byte*& input,
                                  size_t& input_size,
                                  size_t& input_consumed,
                                  size_t desired)
   {
   const size_t space_available = (m_readbuf.size() - m_readbuf_pos);
   const size_t taken = std::min(input_size, desired);

   if(taken > space_available)
      throw TLS_Exception(RECORD_OVERFLOW,
                          "Record is larger than allowed maximum size");

   copy_mem(&m_readbuf[m_readbuf_pos], input, taken);
   m_readbuf_pos += taken;
   input_consumed += taken;
   input_size -= taken;
   input += taken;
   }

/*
* Retrieve the next record
*/
size_t Record_Reader::add_input(const byte input_array[], size_t input_size,
                                size_t& input_consumed,
                                byte& msg_type,
                                MemoryVector<byte>& msg)
   {
   const byte* input = &input_array[0];

   input_consumed = 0;

   const size_t HEADER_SIZE = 5;

   if(m_readbuf_pos < HEADER_SIZE) // header incomplete?
      {
      consume_input(input, input_size, input_consumed, HEADER_SIZE - m_readbuf_pos);

      if(m_readbuf_pos < HEADER_SIZE)
         return (HEADER_SIZE - m_readbuf_pos); // header still incomplete

      BOTAN_ASSERT_EQUAL(m_readbuf_pos, HEADER_SIZE,
                         "Buffer error in SSL header");
      }

   // SSLv2-format client hello?
   if(m_readbuf[0] & 0x80 && m_readbuf[2] == 1 && m_readbuf[3] >= 3)
      {
      size_t record_len = make_u16bit(m_readbuf[0], m_readbuf[1]) & 0x7FFF;

      consume_input(input, input_size, input_consumed, (record_len + 2) - m_readbuf_pos);

      if(m_readbuf_pos < (record_len + 2))
         return ((record_len + 2) - m_readbuf_pos);

      BOTAN_ASSERT_EQUAL(m_readbuf_pos, (record_len + 2),
                         "Buffer error in SSLv2 hello");

      msg_type = HANDSHAKE;

      msg.resize(record_len + 4);

      // Fake v3-style handshake message wrapper
      msg[0] = CLIENT_HELLO_SSLV2;
      msg[1] = 0;
      msg[2] = m_readbuf[0] & 0x7F;
      msg[3] = m_readbuf[1];

      copy_mem(&msg[4], &m_readbuf[2], m_readbuf_pos - 2);
      m_readbuf_pos = 0;
      return 0;
      }

   if(m_readbuf[0] != CHANGE_CIPHER_SPEC &&
      m_readbuf[0] != ALERT &&
      m_readbuf[0] != HANDSHAKE &&
      m_readbuf[0] != APPLICATION_DATA)
      {
      throw TLS_Exception(UNEXPECTED_MESSAGE,
                          "Record_Reader: Unknown record type");
      }

   const u16bit version    = make_u16bit(m_readbuf[1], m_readbuf[2]);
   const u16bit record_len = make_u16bit(m_readbuf[3], m_readbuf[4]);

   if(m_major && (m_readbuf[1] != m_major || m_readbuf[2] != m_minor))
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Record_Reader: Got unexpected version");

   if(record_len > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(RECORD_OVERFLOW,
                          "Got message that exceeds maximum size");

   consume_input(input, input_size, input_consumed,
                 (HEADER_SIZE + record_len) - m_readbuf_pos);

   if(m_readbuf_pos < (HEADER_SIZE + record_len))
      return ((HEADER_SIZE + record_len) - m_readbuf_pos);

   BOTAN_ASSERT_EQUAL(HEADER_SIZE + record_len, m_readbuf_pos,
                      "Bad buffer handling in record body");

   // Null mac means no encryption either, only valid during handshake
   if(m_mac_size == 0)
      {
      if(m_readbuf[0] != CHANGE_CIPHER_SPEC &&
         m_readbuf[0] != ALERT &&
         m_readbuf[0] != HANDSHAKE)
         {
         throw TLS_Exception(DECODE_ERROR, "Invalid msg type received during handshake");
         }

      msg_type = m_readbuf[0];
      msg.resize(record_len);
      copy_mem(&msg[0], &m_readbuf[HEADER_SIZE], record_len);

      m_readbuf_pos = 0;
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext

   // FIXME: process in-place
   m_cipher.process_msg(&m_readbuf[HEADER_SIZE], record_len);
   size_t got_back = m_cipher.read(&m_readbuf[HEADER_SIZE], record_len, Pipe::LAST_MESSAGE);
   BOTAN_ASSERT_EQUAL(got_back, record_len, "Cipher didn't decrypt full amount");

   size_t pad_size = 0;

   if(m_block_size)
      {
      byte pad_value = m_readbuf[HEADER_SIZE + (record_len-1)];
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
            if(m_readbuf[HEADER_SIZE + (record_len-i-1)] != pad_value)
               padding_good = false;

         if(!padding_good)
            pad_size = 0;
         }
      }

   if(record_len < m_mac_size + pad_size + m_iv_size)
      throw Decoding_Error("Record_Reader: Record truncated");

   const u16bit plain_length = record_len - (m_mac_size + pad_size + m_iv_size);

   if(plain_length > m_max_fragment)
      throw TLS_Exception(RECORD_OVERFLOW, "Plaintext record is too large");

   m_mac->update_be(m_seq_no);
   m_mac->update(m_readbuf[0]); // msg_type

   if(version != SSL_V3)
      for(size_t i = 0; i != 2; ++i)
         m_mac->update(get_byte(i, version));

   m_mac->update_be(plain_length);
   m_mac->update(&m_readbuf[HEADER_SIZE + m_iv_size], plain_length);

   ++m_seq_no;

   MemoryVector<byte> computed_mac = m_mac->final();

   if(computed_mac.size() != m_mac_size)
      throw TLS_Exception(INTERNAL_ERROR,
                          "MAC produced value of unexpected size");

   const size_t mac_offset = record_len - (m_mac_size + pad_size);

   if(!same_mem(&m_readbuf[HEADER_SIZE + mac_offset], &computed_mac[0], m_mac_size))
      throw TLS_Exception(BAD_RECORD_MAC, "Record_Reader: MAC failure");

   msg_type = m_readbuf[0];

   msg.resize(plain_length);
   copy_mem(&msg[0], &m_readbuf[HEADER_SIZE + m_iv_size], plain_length);
   m_readbuf_pos = 0;
   return 0;
   }

}
