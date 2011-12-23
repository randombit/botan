/*
* TLS Session Key
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session_key.h>
#include <botan/prf_ssl3.h>
#include <botan/prf_tls.h>
#include <botan/lookup.h>

namespace Botan {

/**
* Return the client cipher key
*/
SymmetricKey SessionKeys::client_cipher_key() const
   {
   return c_cipher;
   }

/**
* Return the server cipher key
*/
SymmetricKey SessionKeys::server_cipher_key() const
   {
   return s_cipher;
   }

/**
* Return the client MAC key
*/
SymmetricKey SessionKeys::client_mac_key() const
   {
   return c_mac;
   }

/**
* Return the server MAC key
*/
SymmetricKey SessionKeys::server_mac_key() const
   {
   return s_mac;
   }

/**
* Return the client cipher IV
*/
InitializationVector SessionKeys::client_iv() const
   {
   return c_iv;
   }

/**
* Return the server cipher IV
*/
InitializationVector SessionKeys::server_iv() const
   {
   return s_iv;
   }

/**
* Return the TLS master secret
*/
SecureVector<byte> SessionKeys::master_secret() const
   {
   return master_sec;
   }

/**
* Generate SSLv3 session keys
*/
SymmetricKey SessionKeys::ssl3_keygen(size_t prf_gen,
                                      const MemoryRegion<byte>& pre_master,
                                      const MemoryRegion<byte>& client_random,
                                      const MemoryRegion<byte>& server_random)
   {
   SSL3_PRF prf;

   SecureVector<byte> salt;
   salt += client_random;
   salt += server_random;

   master_sec = prf.derive_key(48, pre_master, salt);

   salt.clear();
   salt += server_random;
   salt += client_random;

   return prf.derive_key(prf_gen, master_sec, salt);
   }

/**
* Generate TLS 1.0 session keys
*/
SymmetricKey SessionKeys::tls1_keygen(size_t prf_gen,
                                      const MemoryRegion<byte>& pre_master,
                                      const MemoryRegion<byte>& client_random,
                                      const MemoryRegion<byte>& server_random)
   {
   const byte MASTER_SECRET_MAGIC[] = {
      0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
      0x74 };
   const byte KEY_GEN_MAGIC[] = {
      0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F,
      0x6E };

   TLS_PRF prf;

   SecureVector<byte> salt;
   salt += std::make_pair(MASTER_SECRET_MAGIC, sizeof(MASTER_SECRET_MAGIC));
   salt += client_random;
   salt += server_random;

   master_sec = prf.derive_key(48, pre_master, salt);

   salt.clear();
   salt += std::make_pair(KEY_GEN_MAGIC, sizeof(KEY_GEN_MAGIC));
   salt += server_random;
   salt += client_random;

   return prf.derive_key(prf_gen, master_sec, salt);
   }

/**
* SessionKeys Constructor
*/
SessionKeys::SessionKeys(const CipherSuite& suite, Version_Code version,
                         const MemoryRegion<byte>& pre_master_secret,
                         const MemoryRegion<byte>& c_random,
                         const MemoryRegion<byte>& s_random)
   {
   if(version != SSL_V3 && version != TLS_V10 && version != TLS_V11)
      throw Invalid_Argument("SessionKeys: Unknown version code");

   const size_t mac_keylen = output_length_of(suite.mac_algo());
   const size_t cipher_keylen = suite.cipher_keylen();

   size_t cipher_ivlen = 0;
   if(have_block_cipher(suite.cipher_algo()))
      cipher_ivlen = block_size_of(suite.cipher_algo());

   const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_ivlen);

   SymmetricKey keyblock = (version == SSL_V3) ?
      ssl3_keygen(prf_gen, pre_master_secret, c_random, s_random) :
      tls1_keygen(prf_gen, pre_master_secret, c_random, s_random);

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
