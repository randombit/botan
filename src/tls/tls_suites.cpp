/*
* TLS Cipher Suites
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_suites.h>
#include <botan/tls_exceptn.h>

namespace Botan {

/**
* Convert an SSL/TLS ciphersuite to algorithm fields
*/
TLS_Ciphersuite TLS_Ciphersuite::lookup_ciphersuite(u16bit suite)
   {
   switch(suite)
      {
      // RSA ciphersuites

      case TLS_RSA_WITH_AES_128_CBC_SHA:
         return TLS_Ciphersuite("RSA", "", "SHA-1", "AES-128", 16);

      case TLS_RSA_WITH_AES_256_CBC_SHA:
         return TLS_Ciphersuite("RSA", "", "SHA-1", "AES-256", 32);

      case TLS_RSA_WITH_AES_128_CBC_SHA256:
         return TLS_Ciphersuite("RSA", "", "SHA-256", "AES-128", 16);

      case TLS_RSA_WITH_AES_256_CBC_SHA256:
         return TLS_Ciphersuite("RSA", "", "SHA-256", "AES-256", 32);

      case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
         return TLS_Ciphersuite("RSA", "", "SHA-1", "TripleDES", 24);

      case TLS_RSA_WITH_RC4_128_SHA:
         return TLS_Ciphersuite("RSA", "", "SHA-1", "ARC4", 16);

      case TLS_RSA_WITH_RC4_128_MD5:
         return TLS_Ciphersuite("RSA", "", "MD5", "ARC4", 16);

      case TLS_RSA_WITH_SEED_CBC_SHA:
         return TLS_Ciphersuite("RSA", "", "SHA-1", "SEED", 16);

      // DH/DSS ciphersuites

      case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
         return TLS_Ciphersuite("DSA", "DH", "SHA-1", "AES-128", 16);

      case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
         return TLS_Ciphersuite("DSA", "DH", "SHA-1", "AES-256", 32);

      case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
         return TLS_Ciphersuite("DSA", "DH", "SHA-256", "AES-128", 16);

      case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
         return TLS_Ciphersuite("DSA", "DH", "SHA-256", "AES-256", 32);

      case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
         return TLS_Ciphersuite("DSA", "DH", "SHA-1", "TripleDES", 24);

      case TLS_DHE_DSS_WITH_RC4_128_SHA:
         return TLS_Ciphersuite("DSA", "DH", "SHA-1", "ARC4", 16);

      case TLS_DHE_DSS_WITH_SEED_CBC_SHA:
         return TLS_Ciphersuite("DSA", "DH", "SHA-1", "SEED", 16);

      // DH/RSA ciphersuites

      case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
         return TLS_Ciphersuite("RSA", "DH", "SHA-1", "AES-128", 16);

      case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
         return TLS_Ciphersuite("RSA", "DH", "SHA-1", "AES-256", 32);

      case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
         return TLS_Ciphersuite("RSA", "DH", "SHA-256", "AES-128", 16);

      case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
         return TLS_Ciphersuite("RSA", "DH", "SHA-256", "AES-256", 32);

      case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
         return TLS_Ciphersuite("RSA", "DH", "SHA-1", "TripleDES", 24);

      case TLS_DHE_RSA_WITH_SEED_CBC_SHA:
         return TLS_Ciphersuite("RSA", "DH", "SHA-1", "SEED", 16);

      // ECDH/RSA ciphersuites
      case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
         return TLS_Ciphersuite("RSA", "ECDH", "SHA-1", "AES-128", 16);

      case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
         return TLS_Ciphersuite("RSA", "ECDH", "SHA-1", "AES-256", 32);

      case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
         return TLS_Ciphersuite("RSA", "ECDH", "SHA-1", "TripleDES", 24);

      case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
         return TLS_Ciphersuite("RSA", "ECDH", "SHA-1", "ARC4", 16);

      // SRP/RSA ciphersuites

      case TLS_SRP_SHA_RSA_WITH_AES_128_SHA:
         return TLS_Ciphersuite("RSA", "SRP", "SHA-1", "AES-128", 16);

      case TLS_SRP_SHA_RSA_WITH_AES_256_SHA:
         return TLS_Ciphersuite("RSA", "SRP", "SHA-1", "AES-256", 32);

      case TLS_SRP_SHA_RSA_WITH_3DES_EDE_SHA:
         return TLS_Ciphersuite("RSA", "SRP", "SHA-1", "TripleDES", 24);

      // SRP/DSA ciphersuites

      case TLS_SRP_SHA_DSS_WITH_AES_128_SHA:
         return TLS_Ciphersuite("DSA", "SRP", "SHA-1", "AES-128", 16);

      case TLS_SRP_SHA_DSS_WITH_AES_256_SHA:
         return TLS_Ciphersuite("DSA", "SRP", "SHA-1", "AES-256", 32);

      case TLS_SRP_SHA_DSS_WITH_3DES_EDE_SHA:
         return TLS_Ciphersuite("DSA", "SRP", "SHA-1", "TripleDES", 24);

      // ECDH/ECDSA ciphersuites

      case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-1", "AES-128", 16);

      case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-1", "AES-256", 32);

      case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-256", "AES-128", 16);

      case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-384", "AES-256", 32);

      case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-256", "AES-128", 16);

      case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-384", "AES-256", 32);

      case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-1", "ARC4", 16);

      case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
         return TLS_Ciphersuite("ECDSA", "ECDH", "SHA-1", "TripleDES", 24);

      default:
         return TLS_Ciphersuite(); // some unknown ciphersuite
      }
   }

TLS_Ciphersuite::TLS_Ciphersuite(const std::string& sig_algo,
                                 const std::string& kex_algo,
                                 const std::string& mac_algo,
                                 const std::string& cipher_algo,
                                 size_t cipher_algo_keylen) :
   m_sig_algo(sig_algo),
   m_kex_algo(kex_algo),
   m_mac_algo(mac_algo),
   m_cipher_algo(cipher_algo),
   m_cipher_keylen(cipher_algo_keylen)
   {
   }

}
