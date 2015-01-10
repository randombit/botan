/*
* Policies for TLS
* (C) 2004-2010,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
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
   return std::vector<std::string>({
      "ChaCha20Poly1305",
      "AES-256/GCM",
      "AES-128/GCM",
      "AES-256/CCM",
      "AES-128/CCM",
      "AES-256/CCM-8",
      "AES-128/CCM-8",
      //"Camellia-256/GCM",
      //"Camellia-128/GCM",
      "AES-256",
      "AES-128",
      //"Camellia-256",
      //"Camellia-128",
      //"SEED"
      //"3DES",
      //"RC4",
      });
   }

std::vector<std::string> Policy::allowed_signature_hashes() const
   {
   return std::vector<std::string>({
      "SHA-512",
      "SHA-384",
      "SHA-256",
      "SHA-224",
      //"SHA-1",
      //"MD5",
      });
   }

std::vector<std::string> Policy::allowed_macs() const
   {
   return std::vector<std::string>({
      "AEAD",
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
      "brainpool512r1",
      "secp521r1",
      "brainpool384r1",
      "secp384r1",
      "brainpool256r1",
      "secp256r1",
      //"secp256k1",
      //"secp224r1",
      //"secp224k1",
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
   return 86400; // ~1 day
   }

bool Policy::send_fallback_scsv(Protocol_Version version) const
   {
   return version != latest_supported_version(version.is_datagram_protocol());
   }

bool Policy::acceptable_protocol_version(Protocol_Version version) const
   {
   if(version.is_datagram_protocol())
      return (version >= Protocol_Version::DTLS_V12);
   else
      return (version >= Protocol_Version::TLS_V10);
   }

Protocol_Version Policy::latest_supported_version(bool datagram) const
   {
   if(datagram)
      return Protocol_Version::latest_dtls_version();
   else
      return Protocol_Version::latest_tls_version();
   }

bool Policy::acceptable_ciphersuite(const Ciphersuite&) const
   {
   return true;
   }

bool Policy::negotiate_heartbeat_support() const
   {
   return false;
   }

bool Policy::allow_server_initiated_renegotiation() const
   {
   return true;
   }

std::vector<u16bit> Policy::srtp_profiles() const
   {
   return std::vector<u16bit>();
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

std::vector<u16bit> Policy::ciphersuite_list(Protocol_Version version,
                                             bool have_srp) const
   {
   const std::vector<std::string> ciphers = allowed_ciphers();
   const std::vector<std::string> macs = allowed_macs();
   const std::vector<std::string> kex = allowed_key_exchange_methods();
   const std::vector<std::string> sigs = allowed_signature_methods();

   Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);

   std::set<Ciphersuite, Ciphersuite_Preference_Ordering> ciphersuites(order);

   for(auto&& suite : Ciphersuite::all_known_ciphersuites())
      {
      if(!acceptable_ciphersuite(suite))
         continue;

      if(!have_srp && suite.kex_algo() == "SRP_SHA")
         continue;

      if(version.is_datagram_protocol() && suite.cipher_algo() == "RC4")
         continue;

      if(!version.supports_aead_modes() && suite.mac_algo() == "AEAD")
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

   if(ciphersuites.empty())
      throw std::logic_error("Policy does not allow any available cipher suite");

   std::vector<u16bit> ciphersuite_codes;
   for(auto i : ciphersuites)
      ciphersuite_codes.push_back(i.ciphersuite_code());
   return ciphersuite_codes;
   }

}

}
