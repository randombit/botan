/*
* Policies for TLS
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_magic.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace TLS {

std::vector<std::string> Policy::allowed_ciphers() const
   {
   std::vector<std::string> allowed;

   allowed.push_back("AES-256");
   allowed.push_back("AES-128");
   allowed.push_back("3DES");
   allowed.push_back("ARC4");
   //allowed.push_back("Camellia");
   //allowed.push_back("SEED");

   return allowed;
   }

std::vector<std::string> Policy::allowed_hashes() const
   {
   std::vector<std::string> allowed;

   allowed.push_back("SHA-512");
   allowed.push_back("SHA-384");
   allowed.push_back("SHA-256");
   allowed.push_back("SHA-224");
   allowed.push_back("SHA-1");
   //allowed.push_back("MD5");

   return allowed;
   }

std::vector<std::string> Policy::allowed_key_exchange_methods() const
   {
   std::vector<std::string> allowed;

   allowed.push_back("SRP_SHA");
   //allowed.push_back("ECDHE_PSK");
   //allowed.push_back("DHE_PSK");
   //allowed.push_back("PSK");

   allowed.push_back("ECDH");
   allowed.push_back("DH");
   allowed.push_back("RSA");

   return allowed;
   }

std::vector<std::string> Policy::allowed_signature_methods() const
   {
   std::vector<std::string> allowed;

   allowed.push_back("ECDSA");
   allowed.push_back("RSA");
   allowed.push_back("DSA");
   //allowed.push_back("");

   return allowed;
   }

std::vector<std::string> Policy::allowed_ecc_curves() const
   {
   std::vector<std::string> curves;
   curves.push_back("secp521r1");
   curves.push_back("secp384r1");
   curves.push_back("secp256r1");
   curves.push_back("secp256k1");
   curves.push_back("secp224r1");
   curves.push_back("secp224k1");
   curves.push_back("secp192r1");
   curves.push_back("secp192k1");
   curves.push_back("secp160r2");
   curves.push_back("secp160r1");
   curves.push_back("secp160k1");
   return curves;
   }

/*
* Choose an ECC curve to use
*/
std::string Policy::choose_curve(const std::vector<std::string>& curve_names) const
   {
   const std::vector<std::string> our_curves = allowed_ecc_curves();

   for(size_t i = 0; i != our_curves.size(); ++i)
      if(value_exists(curve_names, our_curves[i]))
         return our_curves[i];

   return ""; // no shared curve
   }

/*
* Return allowed compression algorithms
*/
std::vector<byte> Policy::compression() const
   {
   std::vector<byte> algs;
   algs.push_back(NO_COMPRESSION);
   return algs;
   }

u32bit Policy::session_ticket_lifetime() const
   {
   return 86400; // 1 day
   }

Protocol_Version Policy::min_version() const
   {
   return Protocol_Version::SSL_V3;
   }

Protocol_Version Policy::pref_version() const
   {
   return Protocol_Version::TLS_V12;
   }

namespace {

class Ciphersuite_Preference_Ordering
   {
   public:
      Ciphersuite_Preference_Ordering(const std::vector<std::string>& ciphers,
                                      const std::vector<std::string>& hashes,
                                      const std::vector<std::string>& kex,
                                      const std::vector<std::string>& sigs) :
         m_ciphers(ciphers), m_hashes(hashes), m_kex(kex), m_sigs(sigs) {}

      bool operator()(const Ciphersuite& a, const Ciphersuite& b) const
         {
         if(a.kex_algo() != b.kex_algo())
            {
            for(size_t i = 0; i != m_kex.size(); ++i)
               {
               if(a.kex_algo() == m_kex[i])
                  return true;
               if(b.kex_algo() == m_kex[i])
                  return false;
               }
            }

         if(a.cipher_algo() != b.cipher_algo())
            {
            for(size_t i = 0; i != m_ciphers.size(); ++i)
               {
               if(a.cipher_algo() == m_ciphers[i])
                  return true;
               if(b.cipher_algo() == m_ciphers[i])
                  return false;
               }
            }

         if(a.cipher_keylen() != b.cipher_keylen())
            {
            if(a.cipher_keylen() < b.cipher_keylen())
               return false;
            if(a.cipher_keylen() > b.cipher_keylen())
               return true;
            }

         if(a.sig_algo() != b.sig_algo())
            {
            for(size_t i = 0; i != m_sigs.size(); ++i)
               {
               if(a.sig_algo() == m_sigs[i])
                  return true;
               if(b.sig_algo() == m_sigs[i])
                  return false;
               }
            }

         if(a.mac_algo() != b.mac_algo())
            {
            for(size_t i = 0; i != m_hashes.size(); ++i)
               {
               if(a.mac_algo() == m_hashes[i])
                  return true;
               if(b.mac_algo() == m_hashes[i])
                  return false;
               }
            }

         return false; // equal (?!?)
         }
   private:
      std::vector<std::string> m_ciphers, m_hashes, m_kex, m_sigs;

   };

}

std::vector<u16bit> ciphersuite_list(const Policy& policy,
                                     bool have_srp)
   {
   const std::vector<std::string> ciphers = policy.allowed_ciphers();
   const std::vector<std::string> hashes = policy.allowed_hashes();
   const std::vector<std::string> kex = policy.allowed_key_exchange_methods();
   const std::vector<std::string> sigs = policy.allowed_signature_methods();

   Ciphersuite_Preference_Ordering order(ciphers, hashes, kex, sigs);

   std::map<Ciphersuite, u16bit, Ciphersuite_Preference_Ordering>
      ciphersuites(order);

   for(size_t i = 0; i != 65536; ++i)
      {
      Ciphersuite suite = Ciphersuite::by_id(i);

      if(!suite.valid())
         continue; // not a ciphersuite we know, skip

      if(!have_srp && suite.kex_algo() == "SRP_SHA")
         continue;

      if(!value_exists(kex, suite.kex_algo()))
         continue; // unsupported key exchange

      if(!value_exists(ciphers, suite.cipher_algo()))
         continue; // unsupported cipher

      if(!value_exists(hashes, suite.mac_algo()))
         continue; // unsupported MAC algo

      if(!value_exists(sigs, suite.sig_algo()))
         {
         // allow if it's an empty sig algo and we want to use PSK
         if(suite.sig_algo() != "" || !suite.psk_ciphersuite())
            continue;
         }

      // OK, allow it:
      ciphersuites[suite] = i;
      }

   std::vector<u16bit> ciphersuite_codes;

   for(std::map<Ciphersuite, u16bit, Ciphersuite_Preference_Ordering>::iterator i = ciphersuites.begin();
       i != ciphersuites.end(); ++i)
      {
      ciphersuite_codes.push_back(i->second);
      }

   return ciphersuite_codes;
   }

}

}
