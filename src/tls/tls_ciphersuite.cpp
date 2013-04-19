/*
* TLS Cipher Suite
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_ciphersuite.h>
#include <botan/parsing.h>
#include <sstream>
#include <stdexcept>

namespace Botan {

namespace TLS {

namespace {

/*
* This way all work happens at the constuctor call, and we can
* rely on that happening only once in C++11.
*/
std::vector<Ciphersuite> gather_known_ciphersuites()
   {
   std::vector<Ciphersuite> ciphersuites;

   for(size_t i = 0; i != 65536; ++i)
      {
      Ciphersuite suite = Ciphersuite::by_id(i);

      if(!suite.valid())
         continue; // not a ciphersuite we know, skip

      ciphersuites.push_back(suite);
      }

   return ciphersuites;
   }

}

const std::vector<Ciphersuite>& Ciphersuite::all_known_ciphersuites()
   {
   static std::vector<Ciphersuite> all_ciphersuites(gather_known_ciphersuites());
   return all_ciphersuites;
   }

Ciphersuite Ciphersuite::by_name(const std::string& name)
   {
   for(auto suite : all_known_ciphersuites())
      {
      if(suite.to_string() == name)
         return suite;
      }

   return Ciphersuite(); // some unknown ciphersuite
   }

Ciphersuite::Ciphersuite(u16bit ciphersuite_code,
                         const char* sig_algo,
                         const char* kex_algo,
                         const char* cipher_algo,
                         size_t cipher_keylen,
                         size_t cipher_ivlen,
                         const char* mac_algo,
                         size_t mac_keylen,
                         const char* prf_algo) :
   m_ciphersuite_code(ciphersuite_code),
   m_sig_algo(sig_algo),
   m_kex_algo(kex_algo),
   m_cipher_algo(cipher_algo),
   m_mac_algo(mac_algo),
   m_prf_algo(prf_algo),
   m_cipher_keylen(cipher_keylen),
   m_cipher_ivlen(cipher_ivlen),
   m_mac_keylen(mac_keylen)
   {
   }

bool Ciphersuite::psk_ciphersuite() const
   {
   return (kex_algo() == "PSK" ||
           kex_algo() == "DHE_PSK" ||
           kex_algo() == "ECDHE_PSK");
   }

bool Ciphersuite::ecc_ciphersuite() const
   {
   return (kex_algo() == "ECDH" || sig_algo() == "ECDSA");
   }

bool Ciphersuite::valid() const
   {
   if(!m_cipher_keylen)
      return false;

   // fixme: check that all sub-algorithms are enabled

   return true;
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
      else
         out << kex_algo();

      out << '_';
      }

   if(sig_algo() == "DSA")
      out << "DSS_";
   else if(sig_algo() != "")
      out << sig_algo() << '_';

   out << "WITH_";

   if(cipher_algo() == "RC4")
      {
      out << "RC4_128_";
      }
   else
      {
      if(cipher_algo() == "3DES")
         out << "3DES_EDE";
      else if(cipher_algo().find("Camellia") == 0)
         out << "CAMELLIA_" << std::to_string(8*cipher_keylen());
      else
         out << replace_chars(cipher_algo(), {'-', '/'}, '_');

      if(cipher_algo().find("/") != std::string::npos)
         out << "_"; // some explicit mode already included
      else
         out << "_CBC_";
      }

   if(mac_algo() == "SHA-1")
      out << "SHA";
   else if(mac_algo() == "AEAD")
      out << erase_chars(prf_algo(), {'-'});
   else
      out << erase_chars(mac_algo(), {'-'});

   return out.str();
   }

}

}

