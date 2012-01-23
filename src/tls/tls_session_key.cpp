/*
* TLS Session Key
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/lookup.h>
#include <memory>

namespace Botan {

namespace TLS {

namespace {

std::string lookup_prf_name(Protocol_Version version)
   {
   if(version == Protocol_Version::SSL_V3)
      return "SSL3-PRF";
   else if(version == Protocol_Version::TLS_V10 || version == Protocol_Version::TLS_V11)
      return "TLS-PRF";
   else if(version == Protocol_Version::TLS_V12)
      return "TLS-12-PRF(SHA-256)";
   else
      throw Invalid_Argument("Session_Keys: Unknown version code");
   }

}

/**
* Session_Keys Constructor
*/
Session_Keys::Session_Keys(Handshake_State* state,
                           const MemoryRegion<byte>& pre_master_secret,
                           bool resuming)
   {
   const std::string prf_name = lookup_prf_name(state->version);

   const size_t mac_keylen = output_length_of(state->suite.mac_algo());
   const size_t cipher_keylen = state->suite.cipher_keylen();

   size_t cipher_ivlen = 0;
   if(have_block_cipher(state->suite.cipher_algo()))
      cipher_ivlen = block_size_of(state->suite.cipher_algo());

   const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_ivlen);

   const byte MASTER_SECRET_MAGIC[] = {
      0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

   const byte KEY_GEN_MAGIC[] = {
      0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E };

   std::auto_ptr<KDF> prf(get_kdf(prf_name));

   if(resuming)
      {
      master_sec = pre_master_secret;
      }
   else
      {
      SecureVector<byte> salt;

      if(state->version != Protocol_Version::SSL_V3)
         salt += std::make_pair(MASTER_SECRET_MAGIC, sizeof(MASTER_SECRET_MAGIC));

      salt += state->client_hello->random();
      salt += state->server_hello->random();

      master_sec = prf->derive_key(48, pre_master_secret, salt);
      }

   SecureVector<byte> salt;
   if(state->version != Protocol_Version::SSL_V3)
      salt += std::make_pair(KEY_GEN_MAGIC, sizeof(KEY_GEN_MAGIC));
   salt += state->server_hello->random();
   salt += state->client_hello->random();

   SymmetricKey keyblock = prf->derive_key(prf_gen, master_sec, salt);

   const byte* key_data = keyblock.begin();

   c_mac = SymmetricKey(key_data, mac_keylen);
   key_data += mac_keylen;

   s_mac = SymmetricKey(key_data, mac_keylen);
   key_data += mac_keylen;

   c_cipher = SymmetricKey(key_data, cipher_keylen);
   key_data += cipher_keylen;

   s_cipher = SymmetricKey(key_data, cipher_keylen);
   key_data += cipher_keylen;

   c_iv = InitializationVector(key_data, cipher_ivlen);
   key_data += cipher_ivlen;

   s_iv = InitializationVector(key_data, cipher_ivlen);
   }

}

}
