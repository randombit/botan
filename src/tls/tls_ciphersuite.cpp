/*
* TLS Cipher Suites
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_ciphersuite.h>
#include <botan/tls_magic.h>
#include <botan/parsing.h>
#include <sstream>
#include <stdexcept>

namespace Botan {

namespace TLS {

/**
* Convert an SSL/TLS ciphersuite to algorithm fields
*/
Ciphersuite Ciphersuite::lookup_ciphersuite(u16bit suite)
   {
   switch(suite)
      {
      // RSA ciphersuites

      case TLS_RSA_WITH_AES_128_CBC_SHA:
         return Ciphersuite("RSA", "RSA", "SHA-1", "AES-128", 16);

      case TLS_RSA_WITH_AES_256_CBC_SHA:
         return Ciphersuite("RSA", "RSA", "SHA-1", "AES-256", 32);

      case TLS_RSA_WITH_AES_128_CBC_SHA256:
         return Ciphersuite("RSA", "RSA", "SHA-256", "AES-128", 16);

      case TLS_RSA_WITH_AES_256_CBC_SHA256:
         return Ciphersuite("RSA", "RSA", "SHA-256", "AES-256", 32);

      case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("RSA", "RSA", "SHA-1", "3DES", 24);

      case TLS_RSA_WITH_RC4_128_SHA:
         return Ciphersuite("RSA", "RSA", "SHA-1", "ARC4", 16);

      case TLS_RSA_WITH_RC4_128_MD5:
         return Ciphersuite("RSA", "RSA", "MD5", "ARC4", 16);

      case TLS_RSA_WITH_SEED_CBC_SHA:
         return Ciphersuite("RSA", "RSA", "SHA-1", "SEED", 16);

#if defined(BOTAN_HAS_IDEA)
      case TLS_RSA_WITH_IDEA_CBC_SHA:
         return Ciphersuite("RSA", "RSA", "SHA-1", "IDEA", 16);
#endif

      // DH/DSS ciphersuites

      case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
         return Ciphersuite("DSA", "DH", "SHA-1", "AES-128", 16);

      case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
         return Ciphersuite("DSA", "DH", "SHA-1", "AES-256", 32);

      case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
         return Ciphersuite("DSA", "DH", "SHA-256", "AES-128", 16);

      case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
         return Ciphersuite("DSA", "DH", "SHA-256", "AES-256", 32);

      case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("DSA", "DH", "SHA-1", "3DES", 24);

      case TLS_DHE_DSS_WITH_RC4_128_SHA:
         return Ciphersuite("DSA", "DH", "SHA-1", "ARC4", 16);

      case TLS_DHE_DSS_WITH_SEED_CBC_SHA:
         return Ciphersuite("DSA", "DH", "SHA-1", "SEED", 16);

      // DH/RSA ciphersuites

      case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
         return Ciphersuite("RSA", "DH", "SHA-1", "AES-128", 16);

      case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
         return Ciphersuite("RSA", "DH", "SHA-1", "AES-256", 32);

      case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
         return Ciphersuite("RSA", "DH", "SHA-256", "AES-128", 16);

      case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
         return Ciphersuite("RSA", "DH", "SHA-256", "AES-256", 32);

      case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("RSA", "DH", "SHA-1", "3DES", 24);

      case TLS_DHE_RSA_WITH_SEED_CBC_SHA:
         return Ciphersuite("RSA", "DH", "SHA-1", "SEED", 16);

      // ECDH/RSA ciphersuites
      case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
         return Ciphersuite("RSA", "ECDH", "SHA-1", "AES-128", 16);

      case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
         return Ciphersuite("RSA", "ECDH", "SHA-1", "AES-256", 32);

      case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
         return Ciphersuite("RSA", "ECDH", "SHA-256", "AES-128", 16);

      case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("RSA", "ECDH", "SHA-1", "3DES", 24);

      case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
         return Ciphersuite("RSA", "ECDH", "SHA-1", "ARC4", 16);

      // ECDH/ECDSA ciphersuites

      case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
         return Ciphersuite("ECDSA", "ECDH", "SHA-1", "AES-128", 16);

      case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
         return Ciphersuite("ECDSA", "ECDH", "SHA-1", "AES-256", 32);

      case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
         return Ciphersuite("ECDSA", "ECDH", "SHA-256", "AES-128", 16);

      case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
         return Ciphersuite("ECDSA", "ECDH", "SHA-1", "ARC4", 16);

      case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("ECDSA", "ECDH", "SHA-1", "3DES", 24);

#if 0
      case TLS_PSK_WITH_RC4_128_SHA:
         return Ciphersuite("", "PSK", "SHA-1", "ARC4", 16);
      case TLS_PSK_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("", "PSK", "SHA-1", "3DES", 24);
      case TLS_PSK_WITH_AES_128_CBC_SHA:
         return Ciphersuite("", "PSK", "SHA-1", "AES-128", 16);
      case TLS_PSK_WITH_AES_256_CBC_SHA:
         return Ciphersuite("", "PSK", "SHA-1", "AES-256", 32);

      case TLS_DHE_PSK_WITH_RC4_128_SHA:
         return Ciphersuite("", "DHE_PSK", "SHA-1", "ARC4", 16);
      case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
         return Ciphersuite("", "DHE_PSK", "SHA-1", "3DES", 24);
      case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
         return Ciphersuite("", "DHE_PSK", "SHA-1", "AES-128", 16);
      case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
         return Ciphersuite("", "DHE_PSK", "SHA-1", "AES-256", 32);
#endif

      // SRP/RSA ciphersuites

      case TLS_SRP_SHA_RSA_WITH_AES_128_SHA:
         return Ciphersuite("RSA", "SRP", "SHA-1", "AES-128", 16);

      case TLS_SRP_SHA_RSA_WITH_AES_256_SHA:
         return Ciphersuite("RSA", "SRP", "SHA-1", "AES-256", 32);

      case TLS_SRP_SHA_RSA_WITH_3DES_EDE_SHA:
         return Ciphersuite("RSA", "SRP", "SHA-1", "3DES", 24);

      // SRP/DSA ciphersuites

      case TLS_SRP_SHA_DSS_WITH_AES_128_SHA:
         return Ciphersuite("DSA", "SRP", "SHA-1", "AES-128", 16);

      case TLS_SRP_SHA_DSS_WITH_AES_256_SHA:
         return Ciphersuite("DSA", "SRP", "SHA-1", "AES-256", 32);

      case TLS_SRP_SHA_DSS_WITH_3DES_EDE_SHA:
         return Ciphersuite("DSA", "SRP", "SHA-1", "3DES", 24);

      default:
         return Ciphersuite(); // some unknown ciphersuite
      }
   }

std::string Ciphersuite::to_string() const
   {
   if(m_cipher_keylen == 0)
      throw std::runtime_error("Ciphersuite::to_string - no value set");

   std::ostringstream out;

   out << "TLS_";

   if(kex_algo() != "RSA")
      {
      if(kex_algo() == "DH")
         out << "DHE";
      else if(kex_algo() == "ECDH")
         out << "ECDHE";
      else if(kex_algo() == "SRP")
         out << "SRP_SHA";
      else
         out << kex_algo();

      out << '_';
      }

   if(sig_algo() == "DSA")
      out << "DSS_";
   else if(sig_algo() != "")
      out << sig_algo() << '_';

   out << "WITH_";

   if(cipher_algo() == "ARC4")
      {
      out << "RC4_128_";
      }
   else
      {
      if(cipher_algo() == "3DES")
         out << "3DES_EDE";
      else
         out << replace_char(cipher_algo(), '-', '_');

      out << "_CBC_";
      }

   if(mac_algo() == "SHA-1")
      out << "SHA";
   else if(mac_algo() == "SHA-256")
      out << "SHA256";
   else if(mac_algo() == "SHA-384")
      out << "SHA384";
   else
      out << mac_algo();

   return out.str();
   }

Ciphersuite::Ciphersuite(const std::string& sig_algo,
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

}
