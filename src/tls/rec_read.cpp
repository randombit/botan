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
   m_readbuf(TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE)
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

   m_read_cipher.reset();

   m_read_mac.reset();

   m_block_size = 0;
   m_iv_size = 0;
   m_version = Protocol_Version();
   m_read_seq_no = 0;
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

Protocol_Version Record_Reader::get_version() const
   {
   return m_version;
   }

/*
* Set the keys for reading
*/
void Record_Reader::change_cipher_spec(Connection_Side side,
                                       const Ciphersuite& suite,
                                       const Session_Keys& keys,
                                       byte compression_method)
   {
   m_read_cipher.reset();
   m_read_mac.reset();
   m_read_seq_no = 0;

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
      m_read_cipher.append(get_cipher(
                       cipher_algo + "/CBC/NoPadding",
                       cipher_key, iv, DECRYPTION)
         );
      m_block_size = block_size_of(cipher_algo);

      if(m_version.supports_explicit_cbc_ivs())
         m_iv_size = m_block_size;
      else
         m_iv_size = 0;
      }
   else if(have_stream_cipher(cipher_algo))
      {
      m_read_cipher.append(get_cipher(cipher_algo, cipher_key, DECRYPTION));
      m_block_size = 0;
      m_iv_size = 0;
      }
   else
      throw Invalid_Argument("Record_Reader: Unknown cipher " + cipher_algo);

   if(have_hash(mac_algo))
      {
      Algorithm_Factory& af = global_state().algorithm_factory();

      if(m_version == Protocol_Version::SSL_V3)
         m_read_mac.reset(af.make_mac("SSL3-MAC(" + mac_algo + ")"));
      else
         m_read_mac.reset(af.make_mac("HMAC(" + mac_algo + ")"));

      m_read_mac->set_key(mac_key);
      m_macbuf.resize(m_read_mac->output_length());
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

namespace {

/*
* Checks the TLS padding. Returns 0 if the padding is invalid (we
* count the padding_length field as part of the padding size so a
* valid padding will always be at least one byte long), or the
* length of the padding otherwise.
*
* Returning 0 in the error case should ensure the MAC check will fail.
* This approach is suggested in section 6.2.3.2 of RFC 5246.
*
* Also returns 0 if block_size == 0, so can be safely called with a
* stream cipher in use.
*/
size_t tls_padding_check(Protocol_Version version,
                         size_t block_size,
                         const byte record[],
                         size_t record_len)
   {
   if(block_size == 0 || record_len == 0 || record_len % block_size != 0)
      return 0;

   const size_t padding_length = record[(record_len-1)];

   if(padding_length >= record_len)
      return 0;

   /*
   * SSL v3 requires that the padding be less than the block size
   * but not does specify the value of the padding bytes.
   */
   if(version == Protocol_Version::SSL_V3)
      {
      if(padding_length > 0 && padding_length < block_size)
         return (padding_length + 1);
      else
         return 0;
      }

   /*
   * TLS v1.0 and up require all the padding bytes be the same value
   * and allows up to 255 bytes.
   */
   for(size_t i = 0; i != padding_length; ++i)
      if(record[(record_len-i-1)] != padding_length)
         return 0;

   return padding_length + 1;
   }

}

/*
* Retrieve the next record
*/
size_t Record_Reader::add_input(const byte input_array[], size_t input_sz,
                                size_t& consumed,
                                byte& msg_type,
                                std::vector<byte>& msg,
                                u64bit& msg_sequence)
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
   if((!m_read_mac) && (m_readbuf[0] & 0x80) && (m_readbuf[2] == 1))
      {
      if(m_readbuf[3] == 0 && m_readbuf[4] == 2)
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client claims to only support SSLv2, rejecting");

      if(m_readbuf[3] >= 3) // SSLv2 mapped TLS hello, then?
         {
         const size_t record_len = make_u16bit(m_readbuf[0], m_readbuf[1]) & 0x7FFF;

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
         msg_sequence = m_read_seq_no++;
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
   if(!m_read_mac)
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
      msg_sequence = m_read_seq_no++;
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext

   // FIXME: avoid memory allocation by processing in place
   m_read_cipher.process_msg(&m_readbuf[TLS_HEADER_SIZE], record_len);

   const size_t got_back = m_read_cipher.read(&m_readbuf[TLS_HEADER_SIZE],
                                              record_len,
                                              Pipe::LAST_MESSAGE);

   BOTAN_ASSERT_EQUAL(got_back, record_len, "Cipher encrypted full amount");

   BOTAN_ASSERT_EQUAL(m_read_cipher.remaining(Pipe::LAST_MESSAGE), 0,
                      "Cipher had no remaining inputs");

   /*
   * This is actually padding_length + 1 because both the padding and
   * padding_length fields are padding from our perspective.
   */
   const size_t pad_size =
      tls_padding_check(m_version, m_block_size,
                        &m_readbuf[TLS_HEADER_SIZE], record_len);

   const size_t mac_pad_iv_size = m_macbuf.size() + pad_size + m_iv_size;

   if(record_len < mac_pad_iv_size)
      throw Decoding_Error("Record sent with invalid length");

   m_read_mac->update_be(m_read_seq_no);
   m_read_mac->update(m_readbuf[0]); // msg_type

   if(m_version != Protocol_Version::SSL_V3)
      {
      m_read_mac->update(m_version.major_version());
      m_read_mac->update(m_version.minor_version());
      }

   const u16bit plain_length = record_len - mac_pad_iv_size;

   m_read_mac->update_be(plain_length);
   m_read_mac->update(&m_readbuf[TLS_HEADER_SIZE + m_iv_size], plain_length);

   m_read_mac->final(&m_macbuf[0]);

   const size_t mac_offset = record_len - (m_macbuf.size() + pad_size);

   if(!same_mem(&m_readbuf[TLS_HEADER_SIZE + mac_offset], &m_macbuf[0], m_macbuf.size()))
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

   if(plain_length > m_max_fragment)
      throw TLS_Exception(Alert::RECORD_OVERFLOW, "Plaintext record is too large");

   msg_type = m_readbuf[0];
   msg_sequence = m_read_seq_no++;
   msg.assign(&m_readbuf[TLS_HEADER_SIZE + m_iv_size],
              &m_readbuf[TLS_HEADER_SIZE + m_iv_size + plain_length]);

   m_readbuf_pos = 0;
   return 0;
   }

}

}
