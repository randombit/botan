/*
* TLS Record Handling
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_record.h>
#include <botan/libstate.h>
#include <botan/loadstor.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/rounding.h>
#include <botan/internal/assert.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

namespace TLS {

Connection_Cipher_State::Connection_Cipher_State(
   Protocol_Version version,
   Connection_Side side,
   const Ciphersuite& suite,
   const Session_Keys& keys)
   {
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

   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const BlockCipher* bc = af.prototype_block_cipher(cipher_algo))
      {
      m_block_cipher.reset(bc->clone());
      m_block_cipher->set_key(cipher_key);
      m_block_cipher_cbc_state = iv.bits_of();
      m_block_size = bc->block_size();

      if(version.supports_explicit_cbc_ivs())
         m_iv_size = m_block_size;
      else
         m_iv_size = 0;
      }
   else if(const StreamCipher* sc = af.prototype_stream_cipher(cipher_algo))
      {
      m_stream_cipher.reset(sc->clone());
      m_stream_cipher->set_key(cipher_key);
      m_block_size = 0;
      m_iv_size = 0;
      }
   else
      throw Invalid_Argument("Unknown TLS cipher " + cipher_algo);

   if(version == Protocol_Version::SSL_V3)
      m_mac.reset(af.make_mac("SSL3-MAC(" + mac_algo + ")"));
   else
      m_mac.reset(af.make_mac("HMAC(" + mac_algo + ")"));

   m_mac->set_key(mac_key);
   }

size_t write_record(std::vector<byte>& output,
                    byte msg_type, const byte msg[], size_t msg_length,
                    u64bit msg_sequence_number,
                    Protocol_Version version,
                    Connection_Cipher_State* cipherstate,
                    RandomNumberGenerator& rng)
   {
   BOTAN_ASSERT(output.size() >= TLS_HEADER_SIZE + msg_length,
                "Write buffer is big enough");

   output[0] = msg_type;
   output[1] = version.major_version();
   output[2] = version.minor_version();

   if(!cipherstate) // initial unencrypted handshake records
      {
      output[3] = get_byte<u16bit>(0, msg_length);
      output[4] = get_byte<u16bit>(1, msg_length);

      copy_mem(&output[TLS_HEADER_SIZE], msg, msg_length);

      return (TLS_HEADER_SIZE + msg_length);
      }

   cipherstate->mac()->update_be(msg_sequence_number);
   cipherstate->mac()->update(msg_type);

   if(version != Protocol_Version::SSL_V3)
      {
      cipherstate->mac()->update(version.major_version());
      cipherstate->mac()->update(version.minor_version());
      }

   cipherstate->mac()->update(get_byte<u16bit>(0, msg_length));
   cipherstate->mac()->update(get_byte<u16bit>(1, msg_length));
   cipherstate->mac()->update(msg, msg_length);

   const size_t block_size = cipherstate->block_size();
   const size_t iv_size = cipherstate->iv_size();
   const size_t mac_size = cipherstate->mac_size();

   const size_t buf_size = round_up(
      iv_size + msg_length + mac_size + (block_size ? 1 : 0),
      block_size);

   if(buf_size >= MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Record_Writer: Record is too big");

   BOTAN_ASSERT(output.size() >= TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE,
                "Write buffer is big enough");

   output[3] = get_byte<u16bit>(0, buf_size);
   output[4] = get_byte<u16bit>(1, buf_size);

   byte* buf_write_ptr = &output[TLS_HEADER_SIZE];

   if(iv_size)
      {
      rng.randomize(buf_write_ptr, iv_size);
      buf_write_ptr += iv_size;
      }

   copy_mem(buf_write_ptr, msg, msg_length);
   buf_write_ptr += msg_length;

   cipherstate->mac()->final(buf_write_ptr);
   buf_write_ptr += mac_size;

   if(block_size)
      {
      const size_t pad_val =
         buf_size - (iv_size + msg_length + mac_size + 1);

      for(size_t i = 0; i != pad_val + 1; ++i)
         {
         *buf_write_ptr = pad_val;
         buf_write_ptr += 1;
         }
      }

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Produced ciphertext larger than protocol allows");

   if(StreamCipher* sc = cipherstate->stream_cipher())
      {
      sc->cipher1(&output[TLS_HEADER_SIZE], buf_size);
      }
   else if(BlockCipher* bc = cipherstate->block_cipher())
      {
      secure_vector<byte>& cbc_state = cipherstate->cbc_state();

      BOTAN_ASSERT(buf_size % block_size == 0,
                   "Buffer is an even multiple of block size");

      byte* buf = &output[TLS_HEADER_SIZE];

      const size_t blocks = buf_size / block_size;

      xor_buf(&buf[0], &cbc_state[0], block_size);
      bc->encrypt(&buf[0]);

      for(size_t i = 1; i <= blocks; ++i)
         {
         xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
         bc->encrypt(&buf[block_size*i]);
         }

      cbc_state.assign(&buf[block_size*(blocks-1)],
                       &buf[block_size*blocks]);
      }
   else
      throw Internal_Error("NULL cipher not supported");

   return (TLS_HEADER_SIZE + buf_size);
   }

namespace {

size_t fill_buffer_to(std::vector<byte>& readbuf,
                      size_t& readbuf_pos,
                      const byte*& input,
                      size_t& input_size,
                      size_t& input_consumed,
                      size_t desired)
   {
   if(desired <= readbuf_pos)
      return 0; // already have it

   const size_t space_available = (readbuf.size() - readbuf_pos);
   const size_t taken = std::min(input_size, desired - readbuf_pos);

   if(taken > space_available)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Record is larger than allowed maximum size");

   copy_mem(&readbuf[readbuf_pos], input, taken);
   readbuf_pos += taken;
   input_consumed += taken;
   input_size -= taken;
   input += taken;

   return (desired - readbuf_pos); // how many bytes do we still need?
   }

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

size_t read_record(std::vector<byte>& readbuf,
                   size_t& readbuf_pos,
                   const byte input[],
                   size_t input_sz,
                   size_t& consumed,
                   byte& msg_type,
                   std::vector<byte>& msg,
                   u64bit msg_sequence,
                   Protocol_Version version,
                   Connection_Cipher_State* cipherstate)
   {
   consumed = 0;

   if(readbuf_pos < TLS_HEADER_SIZE) // header incomplete?
      {
      if(size_t needed = fill_buffer_to(readbuf, readbuf_pos,
                                        input, input_sz, consumed,
                                        TLS_HEADER_SIZE))
         return needed;

      BOTAN_ASSERT_EQUAL(readbuf_pos, TLS_HEADER_SIZE,
                         "Have an entire header");
      }

   // Possible SSLv2 format client hello
   if((!cipherstate) && (readbuf[0] & 0x80) && (readbuf[2] == 1))
      {
      if(readbuf[3] == 0 && readbuf[4] == 2)
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client claims to only support SSLv2, rejecting");

      if(readbuf[3] >= 3) // SSLv2 mapped TLS hello, then?
         {
         const size_t record_len = make_u16bit(readbuf[0], readbuf[1]) & 0x7FFF;

         if(size_t needed = fill_buffer_to(readbuf, readbuf_pos,
                                           input, input_sz, consumed,
                                           record_len + 2))
            return needed;

         BOTAN_ASSERT_EQUAL(readbuf_pos, (record_len + 2),
                            "Have the entire SSLv2 hello");

         msg_type = HANDSHAKE;

         msg.resize(record_len + 4);

         // Fake v3-style handshake message wrapper
         msg[0] = CLIENT_HELLO_SSLV2;
         msg[1] = 0;
         msg[2] = readbuf[0] & 0x7F;
         msg[3] = readbuf[1];

         copy_mem(&msg[4], &readbuf[2], readbuf_pos - 2);
         readbuf_pos = 0;
         return 0;
         }
      }

   if(readbuf[0] != CHANGE_CIPHER_SPEC &&
      readbuf[0] != ALERT &&
      readbuf[0] != HANDSHAKE &&
      readbuf[0] != APPLICATION_DATA &&
      readbuf[0] != HEARTBEAT)
      {
      throw Unexpected_Message(
         "Unknown record type " + std::to_string(readbuf[0]) +
         " from counterparty");
      }

   const size_t record_len = make_u16bit(readbuf[3], readbuf[4]);

   if(version.major_version())
      {
      if(readbuf[1] != version.major_version() ||
         readbuf[2] != version.minor_version())
         {
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Got unexpected version from counterparty");
         }
      }

   if(record_len > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Got message that exceeds maximum size");

   if(size_t needed = fill_buffer_to(readbuf, readbuf_pos,
                                     input, input_sz, consumed,
                                     TLS_HEADER_SIZE + record_len))
      return needed;

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(TLS_HEADER_SIZE) + record_len,
                      readbuf_pos,
                      "Have the full record");

   if(!cipherstate) // Only handshake messages allowed here
      {
      if(readbuf[0] != CHANGE_CIPHER_SPEC &&
         readbuf[0] != ALERT &&
         readbuf[0] != HANDSHAKE)
         {
         throw Decoding_Error("Invalid msg type received during handshake");
         }

      msg_type = readbuf[0];
      msg.resize(record_len);
      copy_mem(&msg[0], &readbuf[TLS_HEADER_SIZE], record_len);

      readbuf_pos = 0;
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext
   const size_t block_size = cipherstate->block_size();
   const size_t iv_size = cipherstate->iv_size();
   const size_t mac_size = cipherstate->mac_size();

   if(StreamCipher* sc = cipherstate->stream_cipher())
      {
      sc->cipher1(&readbuf[TLS_HEADER_SIZE], record_len);
      }
   else if(BlockCipher* bc = cipherstate->block_cipher())
      {
      secure_vector<byte>& cbc_state = cipherstate->cbc_state();

      BOTAN_ASSERT(record_len % block_size == 0,
                   "Buffer is an even multiple of block size");

      byte* buf = &readbuf[TLS_HEADER_SIZE];

      const size_t blocks = record_len / block_size;

      secure_vector<byte> last_ciphertext(block_size);
      copy_mem(&last_ciphertext[0], &buf[0], block_size);

      bc->decrypt(&buf[0]);
      xor_buf(&buf[0], &cbc_state[0], block_size);

      for(size_t i = 1; i <= blocks; ++i)
         {
         secure_vector<byte> last_ciphertext2(&buf[block_size*i], &buf[block_size*(i+1)]);
         bc->decrypt(&buf[block_size*i]);
         xor_buf(&buf[block_size*i], &last_ciphertext[0], block_size);
         std::swap(last_ciphertext, last_ciphertext2);
         }
      cbc_state = last_ciphertext;
      }
   else
      throw Internal_Error("NULL cipher not supported");

   /*
   * This is actually padding_length + 1 because both the padding and
   * padding_length fields are padding from our perspective.
   */
   const size_t pad_size =
      tls_padding_check(version, block_size,
                        &readbuf[TLS_HEADER_SIZE], record_len);

   const size_t mac_pad_iv_size = mac_size + pad_size + iv_size;

   if(record_len < mac_pad_iv_size)
      throw Decoding_Error("Record sent with invalid length");

   cipherstate->mac()->update_be(msg_sequence);
   cipherstate->mac()->update(readbuf[0]); // msg_type

   if(version != Protocol_Version::SSL_V3)
      {
      cipherstate->mac()->update(version.major_version());
      cipherstate->mac()->update(version.minor_version());
      }

   const u16bit plain_length = record_len - mac_pad_iv_size;

   cipherstate->mac()->update_be(plain_length);
   cipherstate->mac()->update(&readbuf[TLS_HEADER_SIZE + iv_size], plain_length);

   std::vector<byte> mac_buf(mac_size);
   cipherstate->mac()->final(&mac_buf[0]);

   const size_t mac_offset = record_len - (mac_size + pad_size);

   if(!same_mem(&readbuf[TLS_HEADER_SIZE + mac_offset], &mac_buf[0], mac_size))
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

   msg_type = readbuf[0];
   msg.assign(&readbuf[TLS_HEADER_SIZE + iv_size],
              &readbuf[TLS_HEADER_SIZE + iv_size + plain_length]);

   readbuf_pos = 0;
   return 0;
   }

}

}
