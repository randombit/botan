/*
* TLS Record Handling
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/internal/tls_session_key.h>
#include <botan/libstate.h>

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

}

}
