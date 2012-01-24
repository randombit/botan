/*
* Policies for TLS
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_policy.h>
#include <botan/tls_suites.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace TLS {

std::vector<std::string> Policy::allowed_ciphers() const
   {
   std::vector<std::string> allowed;
   allowed.push_back("AES-256");
   allowed.push_back("AES-128");
   allowed.push_back("TripleDES");
   allowed.push_back("ARC4");
   // Note that SEED is not included by default
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
   // Note that MD5 is not included by default
   return allowed;
   }

std::vector<std::string> Policy::allowed_key_exchange_methods() const
   {
   std::vector<std::string> allowed;
   //allowed.push_back("SRP");
   allowed.push_back("ECDH");
   allowed.push_back("DH");
   allowed.push_back(""); // means RSA via server cert
   return allowed;
   }

std::vector<std::string> Policy::allowed_signature_methods() const
   {
   std::vector<std::string> allowed;
   allowed.push_back("ECDSA");
   allowed.push_back("RSA");
   allowed.push_back("DSA");
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

std::vector<u16bit> Policy::ciphersuite_list(bool have_srp) const
   {
   std::vector<std::string> ciphers = allowed_ciphers();
   std::vector<std::string> hashes = allowed_hashes();
   std::vector<std::string> kex = allowed_key_exchange_methods();
   std::vector<std::string> sigs = allowed_signature_methods();

   if(!have_srp)
      {
      std::vector<std::string>::iterator i = std::find(kex.begin(), kex.end(), "SRP");

      if(i != kex.end())
         kex.erase(i);
      }

   Ciphersuite_Preference_Ordering order(ciphers, hashes, kex, sigs);

   std::map<Ciphersuite, u16bit, Ciphersuite_Preference_Ordering> ciphersuites(order);

   // When in doubt use brute force :)
   for(u32bit i = 0; i != 65536; ++i)
      {
      Ciphersuite suite = Ciphersuite::lookup_ciphersuite(i);
      if(suite.cipher_keylen() == 0)
         continue; // not a ciphersuite we know

      if(value_exists(ciphers, suite.cipher_algo()) &&
         value_exists(hashes, suite.mac_algo()) &&
         value_exists(kex, suite.kex_algo()) &&
         value_exists(sigs, suite.sig_algo()))
         {
         ciphersuites[suite] = i;
         }
      }

   std::vector<u16bit> ciphersuite_codes;

   for(std::map<Ciphersuite, u16bit, Ciphersuite_Preference_Ordering>::iterator i = ciphersuites.begin();
       i != ciphersuites.end(); ++i)
      {
      ciphersuite_codes.push_back(i->second);
      }

   return ciphersuite_codes;
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

/*
* Choose an ECC curve to use
*/
std::string Policy::choose_curve(const std::vector<std::string>& curve_names) const
   {
   std::vector<std::string> our_curves;

   for(size_t i = 0; i != our_curves.size(); ++i)
      if(value_exists(curve_names, our_curves[i]))
         return our_curves[i];

   return ""; // no shared curve
   }

/*
* Choose which ciphersuite to use
*/
u16bit Policy::choose_suite(const std::vector<u16bit>& client_suites,
                            const std::vector<std::string>& available_cert_types,
                            bool have_shared_ecc_curve,
                            bool have_srp) const
   {
   for(size_t i = 0; i != client_suites.size(); ++i)
      {
      const u16bit suite_id = client_suites[i];
      Ciphersuite suite = Ciphersuite::lookup_ciphersuite(suite_id);

      if(suite.cipher_keylen() == 0)
         continue; // not a ciphersuite we know

      if(!have_shared_ecc_curve)
         {
         if(suite.kex_algo() == "ECDH" || suite.sig_algo() == "ECDSA")
            continue;
         }

      if(suite.kex_algo() == "SRP" && have_srp)
         return suite_id;

      if(value_exists(available_cert_types, suite.sig_algo()))
         return suite_id;
      }

   return 0; // no shared cipersuite
   }

/*
* Choose which compression algorithm to use
*/
byte Policy::choose_compression(const std::vector<byte>& c_comp) const
   {
   std::vector<byte> s_comp = compression();

   for(size_t i = 0; i != s_comp.size(); ++i)
      for(size_t j = 0; j != c_comp.size(); ++j)
         if(s_comp[i] == c_comp[j])
            return s_comp[i];

   return NO_COMPRESSION;
   }

}

}
