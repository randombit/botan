/*
* Policies for TLS
* (C) 2004-2010,2012,2015,2016 Jack Lloyd
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
   return {
      //"AES-256/OCB(12)",
      //"AES-128/OCB(12)",
      "AES-256/GCM",
      "AES-128/GCM",
      "ChaCha20Poly1305",
      "AES-256/CCM",
      "AES-128/CCM",
      "AES-256/CCM(8)",
      "AES-128/CCM(8)",
      //"Camellia-256/GCM",
      //"Camellia-128/GCM",
      "AES-256",
      "AES-128",
      //"Camellia-256",
      //"Camellia-128",
      //"SEED"
      //"3DES",
      };
   }

std::vector<std::string> Policy::allowed_signature_hashes() const
   {
   return {
      "SHA-512",
      "SHA-384",
      "SHA-256",
      //"SHA-1",
      };
   }

std::vector<std::string> Policy::allowed_macs() const
   {
   return {
      "AEAD",
      "SHA-384",
      "SHA-256",
      "SHA-1",
      };
   }

std::vector<std::string> Policy::allowed_key_exchange_methods() const
   {
   return {
      //"SRP_SHA",
      //"ECDHE_PSK",
      //"DHE_PSK",
      //"PSK",
      "ECDH",
      "DH",
      "RSA",
      };
   }

std::vector<std::string> Policy::allowed_signature_methods() const
   {
   return {
      "ECDSA",
      "RSA",
      "DSA",
      //"" (anon)
      };
   }

bool Policy::allowed_signature_method(const std::string& sig_method) const
   {
   return value_exists(allowed_signature_methods(), sig_method);
   }

std::vector<std::string> Policy::allowed_ecc_curves() const
   {
   return {
      "brainpool512r1",
      "secp521r1",
      "brainpool384r1",
      "secp384r1",
      "brainpool256r1",
      "secp256r1",
      };
   }

bool Policy::allowed_ecc_curve(const std::string& curve) const
   {
   return value_exists(allowed_ecc_curves(), curve);
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

std::string Policy::dh_group() const
   {
   return "modp/ietf/2048";
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

bool Policy::allow_server_initiated_renegotiation() const { return false; }
bool Policy::allow_insecure_renegotiation() const { return false; }
bool Policy::include_time_in_hello_random() const { return true; }
bool Policy::hide_unknown_users() const { return false; }
bool Policy::server_uses_own_ciphersuite_preferences() const { return true; }

// 1 second initial timeout, 60 second max - see RFC 6347 sec 4.2.4.1
size_t Policy::dtls_initial_timeout() const { return 1*1000; }
size_t Policy::dtls_maximum_timeout() const { return 60*1000; }

size_t Policy::dtls_default_mtu() const
   {
   // default MTU is IPv6 min MTU minus UDP/IP headers
   return 1280 - 40 - 8;
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

   std::vector<Ciphersuite> ciphersuites;

   for(auto&& suite : Ciphersuite::all_known_ciphersuites())
      {
      if(!acceptable_ciphersuite(suite))
         continue;

      if(!have_srp && suite.kex_algo() == "SRP_SHA")
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

      // OK, consider it
      ciphersuites.push_back(suite);
      }

   if(ciphersuites.empty())
      throw Exception("Policy does not allow any available cipher suite");

   Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);
   std::sort(ciphersuites.begin(), ciphersuites.end(), order);

   std::vector<u16bit> ciphersuite_codes;
   for(auto i : ciphersuites)
      ciphersuite_codes.push_back(i.ciphersuite_code());
   return ciphersuite_codes;
   }

namespace {

void print_vec(std::ostream& o,
               const char* key,
               const std::vector<std::string>& v)
   {
   o << key << " = ";
   for(size_t i = 0; i != v.size(); ++i)
      {
      o << v[i];
      if(i != v.size() - 1)
         o << ' ';
      }
   o << '\n';
   }

void print_bool(std::ostream& o,
                const char* key, bool b)
   {
   o << key << " = " << (b ? "true" : "false") << '\n';
   }

}

void Policy::print(std::ostream& o) const
   {
   print_vec(o, "ciphers", allowed_ciphers());
   print_vec(o, "macs", allowed_macs());
   print_vec(o, "signature_hashes", allowed_signature_hashes());
   print_vec(o, "signature_methods", allowed_signature_methods());
   print_vec(o, "key_exchange_methods", allowed_key_exchange_methods());
   print_vec(o, "ecc_curves", allowed_ecc_curves());

   print_bool(o, "allow_insecure_renegotiation", allow_insecure_renegotiation());
   print_bool(o, "include_time_in_hello_random", include_time_in_hello_random());
   print_bool(o, "allow_server_initiated_renegotiation", allow_server_initiated_renegotiation());
   print_bool(o, "hide_unknown_users", hide_unknown_users());
   print_bool(o, "server_uses_own_ciphersuite_preferences", server_uses_own_ciphersuite_preferences());
   o << "session_ticket_lifetime = " << session_ticket_lifetime() << '\n';
   o << "dh_group = " << dh_group() << '\n';
   o << "minimum_dh_group_size = " << minimum_dh_group_size() << '\n';
   }

std::vector<std::string> Strict_Policy::allowed_ciphers() const
   {
   return { "ChaCha20Poly1305", "AES-256/GCM", "AES-128/GCM" };
   }

std::vector<std::string> Strict_Policy::allowed_signature_hashes() const
   {
   return { "SHA-512", "SHA-384"};
   }

std::vector<std::string> Strict_Policy::allowed_macs() const
   {
   return { "AEAD" };
   }

std::vector<std::string> Strict_Policy::allowed_key_exchange_methods() const
   {
   return { "ECDH" };
   }

bool Strict_Policy::acceptable_protocol_version(Protocol_Version version) const
   {
   if(version.is_datagram_protocol())
      return (version >= Protocol_Version::DTLS_V12);
   else
      return (version >= Protocol_Version::TLS_V12);
   }

}

}
