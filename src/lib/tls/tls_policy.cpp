/*
* Policies for TLS
* (C) 2004-2010,2012,2015,2016 Jack Lloyd
*     2016 Christian Mainka
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_policy.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_algos.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/stl_util.h>
#include <botan/pk_keys.h>
#include <sstream>

namespace Botan {

namespace TLS {

std::vector<Signature_Scheme> Policy::allowed_signature_schemes() const
   {
   std::vector<Signature_Scheme> schemes;

   for(Signature_Scheme scheme : all_signature_schemes())
      {
      if(signature_scheme_is_known(scheme) == false)
         continue;
      const bool sig_allowed = allowed_signature_method(signature_algorithm_of_scheme(scheme));
      const bool hash_allowed = allowed_signature_hash(hash_function_of_scheme(scheme));

      if(sig_allowed && hash_allowed)
         {
         schemes.push_back(scheme);
         }
      }

   return schemes;
   }

std::vector<Signature_Scheme> Policy::acceptable_signature_schemes() const
   {
   return this->allowed_signature_schemes();
   }

std::vector<std::string> Policy::allowed_ciphers() const
   {
   return {
      //"AES-256/OCB(12)",
      "ChaCha20Poly1305",
      "AES-256/GCM",
      "AES-128/GCM",
      //"AES-256/CCM",
      //"AES-128/CCM",
      //"AES-256/CCM(8)",
      //"AES-128/CCM(8)",
      //"Camellia-256/GCM",
      //"Camellia-128/GCM",
      //"ARIA-256/GCM",
      //"ARIA-128/GCM",
      //"AES-256",
      //"AES-128",
      //"3DES",
      };
   }

std::vector<std::string> Policy::allowed_signature_hashes() const
   {
   return {
      "SHA-512",
      "SHA-384",
      "SHA-256",
      };
   }

std::vector<std::string> Policy::allowed_macs() const
   {
   /*
   SHA-256 is preferred because the Lucky13 countermeasure works
   somewhat better for SHA-256 vs SHA-384:
   https://github.com/randombit/botan/pull/675
   */
   return {
      "AEAD",
      "SHA-256",
      "SHA-384",
      "SHA-1",
      };
   }

std::vector<std::string> Policy::allowed_key_exchange_methods() const
   {
   return {
      //"ECDHE_PSK",
      //"PSK",
      "CECPQ1",
      "ECDH",
      "DH",
      //"RSA",
      //"IMPLICIT",
      //TODO: allow TLS 1.3 ciphers with UNDEFINED kex algo
      };
   }

std::vector<std::string> Policy::allowed_signature_methods() const
   {
   return {
      "ECDSA",
      "RSA",
      //"DSA",
      //"IMPLICIT",
      //TODO: allow TLS 1.3 ciphers with UNDEFINED sig meth
      };
   }

bool Policy::allowed_signature_method(const std::string& sig_method) const
   {
   return value_exists(allowed_signature_methods(), sig_method);
   }

bool Policy::allowed_signature_hash(const std::string& sig_hash) const
   {
   return value_exists(allowed_signature_hashes(), sig_hash);
   }

bool Policy::use_ecc_point_compression() const
   {
   return false;
   }

Group_Params Policy::choose_key_exchange_group(const std::vector<Group_Params>& peer_groups) const
   {
   if(peer_groups.empty())
      return Group_Params::NONE;

   const std::vector<Group_Params> our_groups = key_exchange_groups();

   for(auto g : our_groups)
      {
      if(value_exists(peer_groups, g))
         return g;
      }

   return Group_Params::NONE;
   }

Group_Params Policy::default_dh_group() const
   {
   /*
   * Return the first listed or just default to 2048
   */
   for(auto g : key_exchange_groups())
      {
      if(group_param_is_dh(g))
         return g;
      }

   return Group_Params::FFDHE_2048;
   }

std::vector<Group_Params> Policy::key_exchange_groups() const
   {
   // Default list is ordered by performance
   return {

#if defined(BOTAN_HAS_CURVE_25519)
      Group_Params::X25519,
#endif

      Group_Params::SECP256R1,
      Group_Params::BRAINPOOL256R1,
      Group_Params::SECP384R1,
      Group_Params::BRAINPOOL384R1,
      Group_Params::SECP521R1,
      Group_Params::BRAINPOOL512R1,

      Group_Params::FFDHE_2048,
      Group_Params::FFDHE_3072,
      Group_Params::FFDHE_4096,
      Group_Params::FFDHE_6144,
      Group_Params::FFDHE_8192,
      };
   }

size_t Policy::minimum_dh_group_size() const
   {
   return 2048;
   }

size_t Policy::minimum_ecdsa_group_size() const
   {
   // Here we are at the mercy of whatever the CA signed, but most certs should be 256 bit by now
   return 256;
   }

size_t Policy::minimum_ecdh_group_size() const
   {
   // x25519 is smallest curve currently supported for TLS key exchange
   return 255;
   }

size_t Policy::minimum_signature_strength() const
   {
   return 110;
   }

bool Policy::require_cert_revocation_info() const
   {
   return true;
   }

size_t Policy::minimum_rsa_bits() const
   {
   /* Default assumption is all end-entity certificates should
      be at least 2048 bits these days.

      If you are connecting to arbitrary servers on the Internet
      (ie as a web browser or SMTP client) you'll probably have to reduce this
      to 1024 bits, or perhaps even lower.
   */
   return 2048;
   }

void Policy::check_peer_key_acceptable(const Public_Key& public_key) const
   {
   const std::string algo_name = public_key.algo_name();

   const size_t keylength = public_key.key_length();
   size_t expected_keylength = 0;

   if(algo_name == "RSA")
      {
      expected_keylength = minimum_rsa_bits();
      }
   else if(algo_name == "DH")
      {
      expected_keylength = minimum_dh_group_size();
      }
   else if(algo_name == "ECDH" || algo_name == "Curve25519")
      {
      expected_keylength = minimum_ecdh_group_size();
      }
   else if(algo_name == "ECDSA")
      {
      expected_keylength = minimum_ecdsa_group_size();
      }
   // else some other algo, so leave expected_keylength as zero and the check is a no-op

   if(keylength < expected_keylength)
      throw TLS_Exception(Alert::INSUFFICIENT_SECURITY,
                          "Peer sent " +
                           std::to_string(keylength) + " bit " + algo_name + " key"
                           ", policy requires at least " +
                           std::to_string(expected_keylength));
   }

uint32_t Policy::session_ticket_lifetime() const
   {
   return 86400; // ~1 day
   }

bool Policy::acceptable_protocol_version(Protocol_Version version) const
   {
   if(version == Protocol_Version::TLS_V12 && allow_tls12())
      return true;

#if defined(BOTAN_HAS_TLS_13)
   if(version == Protocol_Version::TLS_V13 && allow_tls13())
      return true;
#endif

   if(version == Protocol_Version::DTLS_V12 && allow_dtls12())
      return true;

   return false;
   }

Protocol_Version Policy::latest_supported_version(bool datagram) const
   {
   if(datagram)
      {
      if(acceptable_protocol_version(Protocol_Version::DTLS_V12))
         return Protocol_Version::DTLS_V12;
      throw Invalid_State("Policy forbids all available DTLS version");
      }
   else
      {
#if defined(BOTAN_HAS_TLS_13)
      if(acceptable_protocol_version(Protocol_Version::TLS_V13))
         return Protocol_Version::TLS_V13;
#endif
      if(acceptable_protocol_version(Protocol_Version::TLS_V12))
         return Protocol_Version::TLS_V12;
      throw Invalid_State("Policy forbids all available TLS version");
      }
   }

bool Policy::acceptable_ciphersuite(const Ciphersuite& ciphersuite) const
   {
   return value_exists(allowed_ciphers(), ciphersuite.cipher_algo()) &&
          value_exists(allowed_macs(), ciphersuite.mac_algo());
   }

bool Policy::allow_client_initiated_renegotiation() const { return false; }
bool Policy::allow_server_initiated_renegotiation() const { return false; }
bool Policy::allow_insecure_renegotiation() const { return false; }
bool Policy::allow_tls12()  const { return true; }
bool Policy::allow_tls13() const 
   {
#if defined(BOTAN_HAS_TLS_13)
   return true;
#else
   return false;
#endif
   }
bool Policy::allow_dtls12() const { return true; }
bool Policy::include_time_in_hello_random() const { return true; }
bool Policy::hide_unknown_users() const { return false; }
bool Policy::server_uses_own_ciphersuite_preferences() const { return true; }
bool Policy::negotiate_encrypt_then_mac() const { return true; }
bool Policy::support_cert_status_message() const { return true; }
bool Policy::allow_resumption_for_renegotiation() const { return true; }
bool Policy::only_resume_with_exact_version() const { return true; }
bool Policy::require_client_certificate_authentication() const { return false; }
bool Policy::request_client_certificate_authentication() const { return require_client_certificate_authentication(); }
bool Policy::abort_connection_on_undesired_renegotiation() const { return false; }
bool Policy::allow_dtls_epoch0_restart() const { return false; }

size_t Policy::maximum_certificate_chain_size() const { return 0; }

// 1 second initial timeout, 60 second max - see RFC 6347 sec 4.2.4.1
size_t Policy::dtls_initial_timeout() const { return 1*1000; }
size_t Policy::dtls_maximum_timeout() const { return 60*1000; }

size_t Policy::dtls_default_mtu() const
   {
   // default MTU is IPv6 min MTU minus UDP/IP headers
   return 1280 - 40 - 8;
   }

std::vector<uint16_t> Policy::srtp_profiles() const
   {
   return std::vector<uint16_t>();
   }

namespace {

class Ciphersuite_Preference_Ordering final
   {
   public:
      Ciphersuite_Preference_Ordering(const std::vector<std::string>& ciphers,
                                      const std::vector<std::string>& macs,
                                      const std::vector<std::string>& kex,
                                      const std::vector<std::string>& sigs) :
         m_ciphers(ciphers), m_macs(macs), m_kex(kex), m_sigs(sigs) {}

      bool operator()(const Ciphersuite& a, const Ciphersuite& b) const
         {
         if(a.kex_method() != b.kex_method())
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

         if(a.auth_method() != b.auth_method())
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

std::vector<uint16_t> Policy::ciphersuite_list(Protocol_Version version) const
   {
   const std::vector<std::string> ciphers = allowed_ciphers();
   const std::vector<std::string> macs = allowed_macs();
   const std::vector<std::string> kex = allowed_key_exchange_methods();
   const std::vector<std::string> sigs = allowed_signature_methods();

   std::vector<Ciphersuite> ciphersuites;

   for(auto&& suite : Ciphersuite::all_known_ciphersuites())
      {
      // Can we use it?
      if(!suite.valid())
         continue;

      // Can we use it in this version?
      if(!suite.usable_in_version(version))
         continue;

      // Is it acceptable to the policy?
      if(!this->acceptable_ciphersuite(suite))
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
         if(suite.auth_method() != Auth_Method::IMPLICIT || !suite.psk_ciphersuite())
            continue;
         }

      /*
      CECPQ1 always uses x25519 for ECDH, so treat the applications
      removal of x25519 from the ECC curve list as equivalent to
      saying they do not trust CECPQ1
      */
      if(suite.kex_method() == Kex_Algo::CECPQ1)
         {
         if(value_exists(key_exchange_groups(), Group_Params::X25519) == false)
            continue;
         }

      // OK, consider it
      ciphersuites.push_back(suite);
      }

   if(ciphersuites.empty())
      {
      throw Invalid_State("Policy does not allow any available cipher suite");
      }

   Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);
   std::sort(ciphersuites.begin(), ciphersuites.end(), order);

   std::vector<uint16_t> ciphersuite_codes;
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

void print_vec(std::ostream& o,
               const char* key,
               const std::vector<Group_Params>& v)
   {
   o << key << " = ";
   for(size_t i = 0; i != v.size(); ++i)
      {
      o << group_param_to_string(v[i]);
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
   print_bool(o, "allow_tls12", allow_tls12());
   print_bool(o, "allow_tls13", allow_tls13());
   print_bool(o, "allow_dtls12", allow_dtls12());
   print_vec(o, "ciphers", allowed_ciphers());
   print_vec(o, "macs", allowed_macs());
   print_vec(o, "signature_hashes", allowed_signature_hashes());
   print_vec(o, "signature_methods", allowed_signature_methods());
   print_vec(o, "key_exchange_methods", allowed_key_exchange_methods());
   print_vec(o, "key_exchange_groups", key_exchange_groups());

   print_bool(o, "allow_insecure_renegotiation", allow_insecure_renegotiation());
   print_bool(o, "include_time_in_hello_random", include_time_in_hello_random());
   print_bool(o, "allow_server_initiated_renegotiation", allow_server_initiated_renegotiation());
   print_bool(o, "hide_unknown_users", hide_unknown_users());
   print_bool(o, "server_uses_own_ciphersuite_preferences", server_uses_own_ciphersuite_preferences());
   print_bool(o, "negotiate_encrypt_then_mac", negotiate_encrypt_then_mac());
   print_bool(o, "support_cert_status_message", support_cert_status_message());
   o << "session_ticket_lifetime = " << session_ticket_lifetime() << '\n';
   o << "minimum_dh_group_size = " << minimum_dh_group_size() << '\n';
   o << "minimum_ecdh_group_size = " << minimum_ecdh_group_size() << '\n';
   o << "minimum_rsa_bits = " << minimum_rsa_bits() << '\n';
   o << "minimum_signature_strength = " << minimum_signature_strength() << '\n';
   }

std::string Policy::to_string() const
   {
   std::ostringstream oss;
   this->print(oss);
   return oss.str();
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
   return { "CECPQ1", "ECDH" };
   }

bool Strict_Policy::allow_tls12()  const { return true;  }
bool Strict_Policy::allow_tls13()  const 
{
#if defined(BOTAN_HAS_TLS_13)
   return true;
#else
   return false;
#endif
}
bool Strict_Policy::allow_dtls12() const { return true;  }

}

}
