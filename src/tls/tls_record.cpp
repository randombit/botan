/*
* TLS Record Handling
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/internal/tls_session_key.h>
#include <botan/libstate.h>
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

}

}
