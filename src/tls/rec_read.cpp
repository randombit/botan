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

namespace TLS {

Record_Reader::Record_Reader() :
   m_readbuf(TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE),
   m_mac(0)
   {
   reset();
   set_maximum_fragment_size(0);
   }

/*
* Reset the state
*/
void Record_Reader::reset()
   {
   m_macbuf.clear();

   zeroise(m_readbuf);
   m_readbuf_pos = 0;

   m_cipher.reset();

   delete m_mac;
   m_mac = 0;

   m_block_size = 0;
   m_iv_size = 0;
   m_version = Protocol_Version();
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
void Record_Reader::set_version(Protocol_Version version)
   {
   m_version = version;
   }

/*
* Set the keys for reading
*/
void Record_Reader::activate(Connection_Side side,
                             const Ciphersuite& suite,
                             const Session_Keys& keys,
                             byte compression_method)
   {
   m_cipher.reset();
   delete m_mac;
   m_mac = 0;
   m_seq_no = 0;

   if(compression_method != NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

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

      if(m_version >= Protocol_Version::TLS_V11)
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

      if(m_version == Protocol_Version::SSL_V3)
         m_mac = af.make_mac("SSL3-MAC(" + mac_algo + ")");
      else
         m_mac = af.make_mac("HMAC(" + mac_algo + ")");

      m_mac->set_key(mac_key);
      m_macbuf.resize(m_mac->output_length());
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown hash " + mac_algo);
   }

size_t Record_Reader::fill_buffer_to(const byte*& input,
                                     size_t& input_size,
                                     size_t& input_consumed,
                                     size_t desired)
   {
   if(desired <= m_readbuf_pos)
      return 0; // already have it

   const size_t space_available = (m_readbuf.size() - m_readbuf_pos);
   const size_t taken = std::min(input_size, desired - m_readbuf_pos);

   if(taken > space_available)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Record is larger than allowed maximum size");

   copy_mem(&m_readbuf[m_readbuf_pos], input, taken);
   m_readbuf_pos += taken;
   input_consumed += taken;
   input_size -= taken;
   input += taken;

   return (desired - m_readbuf_pos); // how many bytes do we still need?
   }

/*
* Retrieve the next record
*/
size_t Record_Reader::add_input(const byte input_array[], size_t input_sz,
                                size_t& consumed,
                                byte& msg_type,
                                MemoryVector<byte>& msg)
   {
   const byte* input = &input_array[0];

   consumed = 0;

   if(m_readbuf_pos < TLS_HEADER_SIZE) // header incomplete?
      {
      if(size_t needed = fill_buffer_to(input, input_sz, consumed, TLS_HEADER_SIZE))
         return needed;

      BOTAN_ASSERT_EQUAL(m_readbuf_pos, TLS_HEADER_SIZE,
                         "Have an entire header");
      }

   // Possible SSLv2 format client hello
   if((!m_mac) && (m_readbuf[0] & 0x80) && (m_readbuf[2] == 1))
      {
      if(m_readbuf[3] == 0 && m_readbuf[4] == 2)
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client claims to only support SSLv2, rejecting");

      if(m_readbuf[3] >= 3) // SSLv2 mapped TLS hello, then?
         {
         size_t record_len = make_u16bit(m_readbuf[0], m_readbuf[1]) & 0x7FFF;

         if(size_t needed = fill_buffer_to(input, input_sz, consumed, record_len + 2))
            return needed;

         BOTAN_ASSERT_EQUAL(m_readbuf_pos, (record_len + 2),
                            "Have the entire SSLv2 hello");

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
      }

   if(m_readbuf[0] != CHANGE_CIPHER_SPEC &&
      m_readbuf[0] != ALERT &&
      m_readbuf[0] != HANDSHAKE &&
      m_readbuf[0] != APPLICATION_DATA &&
      m_readbuf[0] != HEARTBEAT)
      {
      throw Unexpected_Message(
         "Unknown record type " + std::to_string(m_readbuf[0]) +
         " from counterparty");
      }

   const size_t record_len = make_u16bit(m_readbuf[3], m_readbuf[4]);

   if(m_version.major_version())
      {
      if(m_readbuf[1] != m_version.major_version() ||
         m_readbuf[2] != m_version.minor_version())
         {
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Got unexpected version from counterparty");
         }
      }

   if(record_len > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Got message that exceeds maximum size");

   if(size_t needed = fill_buffer_to(input, input_sz, consumed,
                                     TLS_HEADER_SIZE + record_len))
      return needed;

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(TLS_HEADER_SIZE) + record_len,
                      m_readbuf_pos,
                      "Have the full record");

   // Null mac means no encryption either, only valid during handshake
   if(!m_mac)
      {
      if(m_readbuf[0] != CHANGE_CIPHER_SPEC &&
         m_readbuf[0] != ALERT &&
         m_readbuf[0] != HANDSHAKE)
         {
         throw Decoding_Error("Invalid msg type received during handshake");
         }

      msg_type = m_readbuf[0];
      msg.resize(record_len);
      copy_mem(&msg[0], &m_readbuf[TLS_HEADER_SIZE], record_len);

      m_readbuf_pos = 0;
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext

   // FIXME: avoid memory allocation by processing in place
   m_cipher.process_msg(&m_readbuf[TLS_HEADER_SIZE], record_len);
   size_t got_back = m_cipher.read(&m_readbuf[TLS_HEADER_SIZE], record_len, Pipe::LAST_MESSAGE);
   BOTAN_ASSERT_EQUAL(got_back, record_len, "Cipher encrypted full amount");

   BOTAN_ASSERT_EQUAL(m_cipher.remaining(Pipe::LAST_MESSAGE), 0,
                      "Cipher had no remaining inputs");

   size_t pad_size = 0;

   if(m_block_size)
      {
      byte pad_value = m_readbuf[TLS_HEADER_SIZE + (record_len-1)];
      pad_size = pad_value + 1;

      /*
      * Check the padding; if it is wrong, then say we have 0 bytes of
      * padding, which should ensure that the MAC check below does not
      * succeed. This hides a timing channel.
      *
      * This particular countermeasure is recommended in the TLS 1.2
      * spec (RFC 5246) in section 6.2.3.2
      */
      if(m_version == Protocol_Version::SSL_V3)
         {
         if(pad_value > m_block_size)
            pad_size = 0;
         }
      else
         {
         bool padding_good = true;

         for(size_t i = 0; i != pad_size; ++i)
            if(m_readbuf[TLS_HEADER_SIZE + (record_len-i-1)] != pad_value)
               padding_good = false;

         if(!padding_good)
            pad_size = 0;
         }
      }

   const size_t mac_pad_iv_size = m_macbuf.size() + pad_size + m_iv_size;

   if(record_len < mac_pad_iv_size)
      throw Decoding_Error("Record sent with invalid length");

   const u16bit plain_length = record_len - mac_pad_iv_size;

   if(plain_length > m_max_fragment)
      throw TLS_Exception(Alert::RECORD_OVERFLOW, "Plaintext record is too large");

   m_mac->update_be(m_seq_no);
   m_mac->update(m_readbuf[0]); // msg_type

   if(m_version != Protocol_Version::SSL_V3)
      {
      m_mac->update(m_version.major_version());
      m_mac->update(m_version.minor_version());
      }

   m_mac->update_be(plain_length);
   m_mac->update(&m_readbuf[TLS_HEADER_SIZE + m_iv_size], plain_length);

   ++m_seq_no;

   m_mac->final(m_macbuf);

   const size_t mac_offset = record_len - (m_macbuf.size() + pad_size);

   if(!same_mem(&m_readbuf[TLS_HEADER_SIZE + mac_offset], &m_macbuf[0], m_macbuf.size()))
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

   msg_type = m_readbuf[0];

   msg.resize(plain_length);
   copy_mem(&msg[0], &m_readbuf[TLS_HEADER_SIZE + m_iv_size], plain_length);
   m_readbuf_pos = 0;
   return 0;
   }

}

}
