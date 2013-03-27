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
#include <set>

namespace Botan {

namespace TLS {

std::vector<std::string> Policy::allowed_ciphers() const
   {
   return std::vector<std::string>({
      "ARC4",
      "AES-128",
      "AES-256",
      //"3DES",
      //"Camellia-256",
      //"Camellia-128",
      //"SEED"
      });
   }

std::vector<std::string> Policy::allowed_signature_hashes() const
   {
   return std::vector<std::string>({
      "SHA-512",
      "SHA-384",
      "SHA-256",
      "SHA-224",
      "SHA-1",
      //"MD5",
      });
   }

std::vector<std::string> Policy::allowed_macs() const
   {
   return std::vector<std::string>({
      "SHA-384",
      "SHA-256",
      "SHA-1",
      //"MD5",
      });
   }

std::vector<std::string> Policy::allowed_key_exchange_methods() const
   {
   return std::vector<std::string>({
      "SRP_SHA",
      //"ECDHE_PSK",
      //"DHE_PSK",
      //"PSK",
      "ECDH",
      "DH",
      "RSA",
      });
   }

std::vector<std::string> Policy::allowed_signature_methods() const
   {
   return std::vector<std::string>({
      "ECDSA",
      "RSA",
      "DSA",
      //""
      });
   }

std::vector<std::string> Policy::allowed_ecc_curves() const
   {
   return std::vector<std::string>({
      "secp521r1",
      "secp384r1",
      "secp256r1",
      "secp256k1",
      "secp224r1",
      "secp224k1",
      //"secp192r1",
      //"secp192k1",
      //"secp160r2",
      //"secp160r1",
      //"secp160k1",
      });
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

DL_Group Policy::dh_group() const
   {
   return DL_Group("modp/ietf/2048");
   }

size_t Policy::minimum_dh_group_size() const
   {
   return 1024;
   }

/*
* Return allowed compression algorithms
*/
std::vector<byte> Policy::compression() const
   {
   return std::vector<byte>{ NO_COMPRESSION };
   }

u32bit Policy::session_ticket_lifetime() const
   {
   return 86400; // 1 day
   }

bool Policy::acceptable_protocol_version(Protocol_Version version) const
   {
   return version.known_version(); // accept any version we know about

   // maybe someday...
   //return version >= Protocol_Version::TLS_V11;
   }

bool Policy::server_uses_own_ciphersuite_preferences() const
   {
   return true;
   }

namespace {

class Ciphersuite_Preference_Ordering
   {
   public:
      Ciphersuite_Preference_Ordering(const std::vector<std::string>& ciphers,
                                      const std::vector<std::string>& macs,
                                      const std::vector<std::string>& kex,
                                      const std::vector<std::string>& sigs) :
         m_ciphers(ciphers), m_macs(macs), m_kex(kex), m_sigs(sigs) {}

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
            for(size_t i = 0; i != m_macs.size(); ++i)
               {
               if(a.mac_algo() == m_macs[i])
                  return true;
               if(b.mac_algo() == m_macs[i])
                  return false;
               }
            }

         return false; // equal (?!?)
         }
   private:
      std::vector<std::string> m_ciphers, m_macs, m_kex, m_sigs;
   };

}

std::vector<u16bit> ciphersuite_list(const Policy& policy,
                                     Protocol_Version version,
                                     bool have_srp)
   {
   const std::vector<std::string> ciphers = policy.allowed_ciphers();
   const std::vector<std::string> macs = policy.allowed_macs();
   const std::vector<std::string> kex = policy.allowed_key_exchange_methods();
   const std::vector<std::string> sigs = policy.allowed_signature_methods();

   Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);

   std::set<Ciphersuite, Ciphersuite_Preference_Ordering> ciphersuites(order);

   for(auto suite : Ciphersuite::all_known_ciphersuites())
      {
      if(!have_srp && suite.kex_algo() == "SRP_SHA")
         continue;

      if(version.is_datagram_protocol() && suite.cipher_algo() == "ARC4")
         continue;

      if(!value_exists(kex, suite.kex_algo()))
         continue; // unsupported key exchange

      if(!value_exists(ciphers, suite.cipher_algo()))
         continue; // unsupported cipher

      if(!value_exists(macs, suite.mac_algo()))
         continue; // unsupported MAC algo

      if(!value_exists(sigs, suite.sig_algo()))
         {
         // allow if it's an empty sig algo and we want to use PSK
         if(suite.sig_algo() != "" || !suite.psk_ciphersuite())
            continue;
         }

      // OK, allow it:
      ciphersuites.insert(suite);
      }

   std::vector<u16bit> ciphersuite_codes;
   for(auto i : ciphersuites)
      ciphersuite_codes.push_back(i.ciphersuite_code());
   return ciphersuite_codes;
   }

}

}
