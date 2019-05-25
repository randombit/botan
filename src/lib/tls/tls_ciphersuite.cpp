/*
* TLS Cipher Suite
* (C) 2004-2010,2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_ciphersuite.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <algorithm>

namespace Botan {

namespace TLS {

size_t Ciphersuite::nonce_bytes_from_handshake() const
   {
   switch(m_nonce_format)
      {
      case Nonce_Format::CBC_MODE:
         {
         if(cipher_algo() == "3DES")
            return 8;
         else
            return 16;
         }
      case Nonce_Format::AEAD_IMPLICIT_4:
         return 4;
      case Nonce_Format::AEAD_XOR_12:
         return 12;
      }

   throw Invalid_State("In Ciphersuite::nonce_bytes_from_handshake invalid enum value");
   }

size_t Ciphersuite::nonce_bytes_from_record(Protocol_Version version) const
   {
   switch(m_nonce_format)
      {
      case Nonce_Format::CBC_MODE:
         {
         if(version.supports_explicit_cbc_ivs())
            {
            return cipher_algo() == "3DES" ? 8 : 16;
            }
         else
            {
            return 0;
            }
         }
      case Nonce_Format::AEAD_IMPLICIT_4:
         return 8;
      case Nonce_Format::AEAD_XOR_12:
         return 0;
      }

   throw Invalid_State("In Ciphersuite::nonce_bytes_from_handshake invalid enum value");
   }

bool Ciphersuite::is_scsv(uint16_t suite)
   {
   // TODO: derive from IANA file in script
   return (suite == 0x00FF || suite == 0x5600);
   }

bool Ciphersuite::psk_ciphersuite() const
   {
   return kex_method() == Kex_Algo::PSK ||
          kex_method() == Kex_Algo::DHE_PSK ||
          kex_method() == Kex_Algo::ECDHE_PSK;
   }

bool Ciphersuite::ecc_ciphersuite() const
   {
   return kex_method() == Kex_Algo::ECDH ||
          kex_method() == Kex_Algo::ECDHE_PSK ||
          auth_method() == Auth_Method::ECDSA;
   }

bool Ciphersuite::usable_in_version(Protocol_Version version) const
   {
   if(!version.supports_aead_modes())
      {
      // Old versions do not support AEAD, or any MAC but SHA-1
      if(mac_algo() != "SHA-1")
         return false;
      }

   return true;
   }

bool Ciphersuite::cbc_ciphersuite() const
   {
   return (mac_algo() != "AEAD");
   }

bool Ciphersuite::signature_used() const
   {
   return auth_method() != Auth_Method::ANONYMOUS &&
          auth_method() != Auth_Method::IMPLICIT;
   }

Ciphersuite Ciphersuite::by_id(uint16_t suite)
   {
   const std::vector<Ciphersuite>& all_suites = all_known_ciphersuites();
   auto s = std::lower_bound(all_suites.begin(), all_suites.end(), suite);

   if(s != all_suites.end() && s->ciphersuite_code() == suite)
      {
      return *s;
      }

   return Ciphersuite(); // some unknown ciphersuite
   }

Ciphersuite Ciphersuite::from_name(const std::string& name)
   {
   const std::vector<Ciphersuite>& all_suites = all_known_ciphersuites();

   for(auto suite : all_suites)
      {
      if(suite.to_string() == name)
         return suite;
      }

   return Ciphersuite(); // some unknown ciphersuite
   }

namespace {

bool have_hash(const std::string& prf)
   {
   return (HashFunction::providers(prf).size() > 0);
   }

bool have_cipher(const std::string& cipher)
   {
   return (BlockCipher::providers(cipher).size() > 0) ||
      (StreamCipher::providers(cipher).size() > 0);
   }

}

bool Ciphersuite::is_usable() const
   {
   if(!m_cipher_keylen) // uninitialized object
      return false;

   if(!have_hash(prf_algo()))
      return false;

#if !defined(BOTAN_HAS_TLS_CBC)
   if(cbc_ciphersuite())
      return false;
#endif

   if(mac_algo() == "AEAD")
      {
      if(cipher_algo() == "ChaCha20Poly1305")
         {
#if !defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
         return false;
#endif
         }
      else
         {
         auto cipher_and_mode = split_on(cipher_algo(), '/');
         BOTAN_ASSERT(cipher_and_mode.size() == 2, "Expected format for AEAD algo");
         if(!have_cipher(cipher_and_mode[0]))
            return false;

         const auto mode = cipher_and_mode[1];

#if !defined(BOTAN_HAS_AEAD_CCM)
         if(mode == "CCM" || mode == "CCM-8")
            return false;
#endif

#if !defined(BOTAN_HAS_AEAD_GCM)
         if(mode == "GCM")
            return false;
#endif

#if !defined(BOTAN_HAS_AEAD_OCB)
         if(mode == "OCB(12)" || mode == "OCB")
            return false;
#endif
         }
      }
   else
      {
      // Old non-AEAD schemes
      if(!have_cipher(cipher_algo()))
         return false;
      if(!have_hash(mac_algo())) // HMAC
         return false;
      }

   if(kex_method() == Kex_Algo::SRP_SHA)
      {
#if !defined(BOTAN_HAS_SRP6)
      return false;
#endif
      }
   else if(kex_method() == Kex_Algo::ECDH || kex_method() == Kex_Algo::ECDHE_PSK)
      {
#if !defined(BOTAN_HAS_ECDH)
      return false;
#endif
      }
   else if(kex_method() == Kex_Algo::DH || kex_method() == Kex_Algo::DHE_PSK)
      {
#if !defined(BOTAN_HAS_DIFFIE_HELLMAN)
      return false;
#endif
      }
   else if(kex_method() == Kex_Algo::CECPQ1)
      {
#if !defined(BOTAN_HAS_CECPQ1)
      return false;
#endif
      }

   if(auth_method() == Auth_Method::DSA)
      {
#if !defined(BOTAN_HAS_DSA)
      return false;
#endif
      }
   else if(auth_method() == Auth_Method::ECDSA)
      {
#if !defined(BOTAN_HAS_ECDSA)
      return false;
#endif
      }
   else if(auth_method() == Auth_Method::RSA)
      {
#if !defined(BOTAN_HAS_RSA)
      return false;
#endif
      }

   return true;
   }

}

}

