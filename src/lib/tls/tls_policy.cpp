/*
* Policies for TLS
* (C) 2004-2010,2012,2015,2016 Jack Lloyd
*     2016 Christian Mainka
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_policy.h>

#include <botan/pk_keys.h>
#include <botan/tls_algos.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/stl_util.h>
#include <optional>
#include <sstream>

namespace Botan::TLS {

bool Policy::allow_ssl_key_log_file() const {
   return false;
}

std::vector<Signature_Scheme> Policy::allowed_signature_schemes() const {
   std::vector<Signature_Scheme> schemes;

   for(Signature_Scheme scheme : Signature_Scheme::all_available_schemes()) {
      const bool sig_allowed = allowed_signature_method(scheme.algorithm_name());
      const bool hash_allowed = allowed_signature_hash(scheme.hash_function_name());

      if(sig_allowed && hash_allowed) {
         schemes.push_back(scheme);
      }
   }

   return schemes;
}

std::vector<Signature_Scheme> Policy::acceptable_signature_schemes() const {
   return this->allowed_signature_schemes();
}

std::optional<std::vector<Signature_Scheme>> Policy::acceptable_certificate_signature_schemes() const {
   // the restrictions of ::acceptable_signature_schemes() shall apply
   return std::nullopt;
}

std::vector<std::string> Policy::allowed_ciphers() const {
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

std::vector<std::string> Policy::allowed_signature_hashes() const {
   return {
      "SHA-512",
      "SHA-384",
      "SHA-256",
   };
}

std::vector<std::string> Policy::allowed_macs() const {
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

std::vector<std::string> Policy::allowed_key_exchange_methods() const {
   return {
      //"ECDHE_PSK",
      //"PSK",
      "ECDH",
      "DH",
      //"RSA",
   };
}

std::vector<std::string> Policy::allowed_signature_methods() const {
   return {
      "ECDSA", "RSA",
      //"IMPLICIT",
   };
}

bool Policy::allowed_signature_method(std::string_view sig_method) const {
   return value_exists(allowed_signature_methods(), sig_method);
}

bool Policy::allowed_signature_hash(std::string_view sig_hash) const {
   return value_exists(allowed_signature_hashes(), sig_hash);
}

bool Policy::use_ecc_point_compression() const {
   return false;
}

Group_Params Policy::choose_key_exchange_group(const std::vector<Group_Params>& supported_by_peer,
                                               const std::vector<Group_Params>& offered_by_peer) const {
   if(supported_by_peer.empty()) {
      return Group_Params::NONE;
   }

   const auto our_groups = key_exchange_groups();

   // First check if the peer sent a PQ share of a group we also support
   for(auto share : offered_by_peer) {
      if(share.is_post_quantum() && value_exists(our_groups, share)) {
         return share;
      }
   }

   // Then check if the peer offered a PQ algo we also support
   for(auto share : supported_by_peer) {
      if(share.is_post_quantum() && value_exists(our_groups, share)) {
         return share;
      }
   }

   // Prefer groups that were offered by the peer for the sake of saving
   // an additional round trip. For TLS 1.2, this won't be used.
   for(auto g : offered_by_peer) {
      if(value_exists(our_groups, g)) {
         return g;
      }
   }

   // If no pre-offered groups fit our supported set, we prioritize our
   // own preference.
   for(auto g : our_groups) {
      if(value_exists(supported_by_peer, g)) {
         return g;
      }
   }

   return Group_Params::NONE;
}

Group_Params Policy::default_dh_group() const {
   /*
   * Return the first listed or just default to 2048
   */
   for(auto g : key_exchange_groups()) {
      if(g.is_dh_named_group()) {
         return g;
      }
   }

   return Group_Params::FFDHE_2048;
}

std::vector<Group_Params> Policy::key_exchange_groups() const {
   return {
      // clang-format off
#if defined(BOTAN_HAS_X25519)
      Group_Params::X25519,
#endif

      Group_Params::SECP256R1,

#if defined(BOTAN_HAS_X25519) && defined(BOTAN_HAS_ML_KEM) && defined(BOTAN_HAS_TLS_13_PQC)
      Group_Params_Code::HYBRID_X25519_ML_KEM_768,
#endif

#if defined(BOTAN_HAS_X448)
      Group_Params::X448,
#endif

      Group_Params::SECP384R1,
      Group_Params::SECP521R1,

      Group_Params::BRAINPOOL256R1,
      Group_Params::BRAINPOOL384R1,
      Group_Params::BRAINPOOL512R1,

      Group_Params::FFDHE_2048,
      Group_Params::FFDHE_3072,

      // clang-format on
   };
}

std::vector<Group_Params> Policy::key_exchange_groups_to_offer() const {
   std::vector<Group_Params> groups_to_offer;

   const auto supported_groups = key_exchange_groups();
   BOTAN_ASSERT(!supported_groups.empty(), "Policy allows at least one key exchange group");

   /*
   * Initially prefer sending a key share only of the first pure-ECC
   * group, since these shares are small and PQ support is still not
   * that widespread.
   */
   for(auto group : key_exchange_groups()) {
      if(group.is_pure_ecc_group()) {
         groups_to_offer.push_back(group);
         break;
      }
   }

   /*
   * If for some reason no pure ECC groups are enabled then simply
   * send a share of whatever the policys top preference is.
   */
   if(groups_to_offer.empty()) {
      groups_to_offer.push_back(supported_groups.front());
   }

   return groups_to_offer;
}

size_t Policy::minimum_dh_group_size() const {
   return 2048;
}

size_t Policy::minimum_ecdsa_group_size() const {
   // Here we are at the mercy of whatever the CA signed, but most certs should be 256 bit by now
   return 256;
}

size_t Policy::minimum_ecdh_group_size() const {
   // x25519 is smallest curve currently supported for TLS key exchange
   return 255;
}

size_t Policy::minimum_signature_strength() const {
   return 110;
}

bool Policy::require_cert_revocation_info() const {
   return true;
}

size_t Policy::minimum_rsa_bits() const {
   /* Default assumption is all end-entity certificates should
      be at least 2048 bits these days.

      If you are connecting to arbitrary servers on the Internet
      (ie as a web browser or SMTP client) you'll probably have to reduce this
      to 1024 bits, or perhaps even lower.
   */
   return 2048;
}

void Policy::check_peer_key_acceptable(const Public_Key& public_key) const {
   const std::string algo_name = public_key.algo_name();

   const size_t keylength = public_key.key_length();
   size_t expected_keylength = 0;

   if(algo_name == "RSA") {
      expected_keylength = minimum_rsa_bits();
   } else if(algo_name == "DH") {
      expected_keylength = minimum_dh_group_size();
   } else if(algo_name == "ECDH" || algo_name == "X25519" || algo_name == "X448") {
      expected_keylength = minimum_ecdh_group_size();
   } else if(algo_name == "ECDSA") {
      expected_keylength = minimum_ecdsa_group_size();
   }
   // else some other algo, so leave expected_keylength as zero and the check is a no-op

   if(keylength < expected_keylength) {
      throw TLS_Exception(Alert::InsufficientSecurity,
                          "Peer sent " + std::to_string(keylength) + " bit " + algo_name +
                             " key"
                             ", policy requires at least " +
                             std::to_string(expected_keylength));
   }
}

size_t Policy::maximum_session_tickets_per_client_hello() const {
   return 1;
}

std::chrono::seconds Policy::session_ticket_lifetime() const {
   return std::chrono::days(1);
}

bool Policy::reuse_session_tickets() const {
   return false;
}

size_t Policy::new_session_tickets_upon_handshake_success() const {
   return 1;
}

bool Policy::acceptable_protocol_version(Protocol_Version version) const {
#if defined(BOTAN_HAS_TLS_13)
   if(version == Protocol_Version::TLS_V13 && allow_tls13()) {
      return true;
   }
#endif

#if defined(BOTAN_HAS_TLS_12)
   if(version == Protocol_Version::TLS_V12 && allow_tls12()) {
      return true;
   }

   if(version == Protocol_Version::DTLS_V12 && allow_dtls12()) {
      return true;
   }
#endif

   return false;
}

Protocol_Version Policy::latest_supported_version(bool datagram) const {
   if(datagram) {
      if(acceptable_protocol_version(Protocol_Version::DTLS_V12)) {
         return Protocol_Version::DTLS_V12;
      }
      throw Invalid_State("Policy forbids all available DTLS version");
   } else {
#if defined(BOTAN_HAS_TLS_13)
      if(acceptable_protocol_version(Protocol_Version::TLS_V13)) {
         return Protocol_Version::TLS_V13;
      }
#endif
      if(acceptable_protocol_version(Protocol_Version::TLS_V12)) {
         return Protocol_Version::TLS_V12;
      }
      throw Invalid_State("Policy forbids all available TLS version");
   }
}

bool Policy::acceptable_ciphersuite(const Ciphersuite& ciphersuite) const {
   return value_exists(allowed_ciphers(), ciphersuite.cipher_algo()) &&
          value_exists(allowed_macs(), ciphersuite.mac_algo());
}

bool Policy::allow_client_initiated_renegotiation() const {
   return false;
}

bool Policy::allow_server_initiated_renegotiation() const {
   return false;
}

bool Policy::allow_insecure_renegotiation() const {
   return false;
}

bool Policy::allow_tls12() const {
#if defined(BOTAN_HAS_TLS_12)
   return true;
#else
   return false;
#endif
}

bool Policy::allow_tls13() const {
#if defined(BOTAN_HAS_TLS_13)
   return true;
#else
   return false;
#endif
}

bool Policy::allow_dtls12() const {
#if defined(BOTAN_HAS_TLS_12)
   return true;
#else
   return false;
#endif
}

bool Policy::include_time_in_hello_random() const {
   return true;
}

bool Policy::hide_unknown_users() const {
   return false;
}

bool Policy::server_uses_own_ciphersuite_preferences() const {
   return true;
}

bool Policy::negotiate_encrypt_then_mac() const {
   return true;
}

std::optional<uint16_t> Policy::record_size_limit() const {
   return std::nullopt;
}

bool Policy::support_cert_status_message() const {
   return true;
}

bool Policy::allow_resumption_for_renegotiation() const {
   return true;
}

bool Policy::tls_13_middlebox_compatibility_mode() const {
   return true;
}

bool Policy::hash_hello_random() const {
   return true;
}

bool Policy::only_resume_with_exact_version() const {
   return true;
}

bool Policy::require_client_certificate_authentication() const {
   return false;
}

bool Policy::request_client_certificate_authentication() const {
   return require_client_certificate_authentication();
}

bool Policy::abort_connection_on_undesired_renegotiation() const {
   return false;
}

std::vector<Certificate_Type> Policy::accepted_client_certificate_types() const {
   return {Certificate_Type::X509};
}

std::vector<Certificate_Type> Policy::accepted_server_certificate_types() const {
   return {Certificate_Type::X509};
}

bool Policy::allow_dtls_epoch0_restart() const {
   return false;
}

size_t Policy::maximum_certificate_chain_size() const {
   return 0;
}

// 1 second initial timeout, 60 second max - see RFC 6347 sec 4.2.4.1
size_t Policy::dtls_initial_timeout() const {
   return 1 * 1000;
}

size_t Policy::dtls_maximum_timeout() const {
   return 60 * 1000;
}

size_t Policy::dtls_default_mtu() const {
   // default MTU is IPv6 min MTU minus UDP/IP headers
   return 1280 - 40 - 8;
}

std::vector<uint16_t> Policy::srtp_profiles() const {
   return std::vector<uint16_t>();
}

namespace {

class Ciphersuite_Preference_Ordering final {
   public:
      Ciphersuite_Preference_Ordering(const std::vector<std::string>& ciphers,
                                      const std::vector<std::string>& macs,
                                      const std::vector<std::string>& kex,
                                      const std::vector<std::string>& sigs) :
            m_ciphers(ciphers), m_macs(macs), m_kex(kex), m_sigs(sigs) {}

      bool operator()(const Ciphersuite& a, const Ciphersuite& b) const {
         if(a.kex_method() != b.kex_method()) {
            for(const auto& i : m_kex) {
               if(a.kex_algo() == i) {
                  return true;
               }
               if(b.kex_algo() == i) {
                  return false;
               }
            }
         }

         if(a.cipher_algo() != b.cipher_algo()) {
            for(const auto& m_cipher : m_ciphers) {
               if(a.cipher_algo() == m_cipher) {
                  return true;
               }
               if(b.cipher_algo() == m_cipher) {
                  return false;
               }
            }
         }

         if(a.cipher_keylen() != b.cipher_keylen()) {
            if(a.cipher_keylen() < b.cipher_keylen()) {
               return false;
            }
            if(a.cipher_keylen() > b.cipher_keylen()) {
               return true;
            }
         }

         if(a.auth_method() != b.auth_method()) {
            for(const auto& m_sig : m_sigs) {
               if(a.sig_algo() == m_sig) {
                  return true;
               }
               if(b.sig_algo() == m_sig) {
                  return false;
               }
            }
         }

         if(a.mac_algo() != b.mac_algo()) {
            for(const auto& m_mac : m_macs) {
               if(a.mac_algo() == m_mac) {
                  return true;
               }
               if(b.mac_algo() == m_mac) {
                  return false;
               }
            }
         }

         return false;  // equal (?!?)
      }

   private:
      std::vector<std::string> m_ciphers, m_macs, m_kex, m_sigs;
};

}  // namespace

std::vector<uint16_t> Policy::ciphersuite_list(Protocol_Version version) const {
   const std::vector<std::string> ciphers = allowed_ciphers();
   const std::vector<std::string> macs = allowed_macs();
   const std::vector<std::string> kex = allowed_key_exchange_methods();
   const std::vector<std::string> sigs = allowed_signature_methods();

   std::vector<Ciphersuite> ciphersuites;

   for(auto&& suite : Ciphersuite::all_known_ciphersuites()) {
      // Can we use it?
      if(!suite.valid()) {
         continue;
      }

      // Can we use it in this version?
      if(!suite.usable_in_version(version)) {
         continue;
      }

      // Is it acceptable to the policy?
      if(!this->acceptable_ciphersuite(suite)) {
         continue;
      }

      if(!value_exists(ciphers, suite.cipher_algo())) {
         continue;  // unsupported cipher
      }

      // these checks are irrelevant for TLS 1.3
      // TODO: consider making a method for this logic
      if(version.is_pre_tls_13()) {
         if(!value_exists(kex, suite.kex_algo())) {
            continue;  // unsupported key exchange
         }

         if(!value_exists(macs, suite.mac_algo())) {
            continue;  // unsupported MAC algo
         }

         if(!value_exists(sigs, suite.sig_algo())) {
            // allow if it's an empty sig algo and we want to use PSK
            if(suite.auth_method() != Auth_Method::IMPLICIT || !suite.psk_ciphersuite()) {
               continue;
            }
         }
      }

      // OK, consider it
      ciphersuites.push_back(suite);
   }

   if(ciphersuites.empty()) {
      throw Invalid_State("Policy does not allow any available cipher suite");
   }

   Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);
   std::sort(ciphersuites.begin(), ciphersuites.end(), order);

   std::vector<uint16_t> ciphersuite_codes;
   ciphersuite_codes.reserve(ciphersuites.size());
   for(auto i : ciphersuites) {
      ciphersuite_codes.push_back(i.ciphersuite_code());
   }
   return ciphersuite_codes;
}

namespace {

void print_vec(std::ostream& o, const char* key, const std::vector<std::string>& v) {
   o << key << " = ";
   for(size_t i = 0; i != v.size(); ++i) {
      o << v[i];
      if(i != v.size() - 1) {
         o << ' ';
      }
   }
   o << '\n';
}

void print_vec(std::ostream& o, const char* key, const std::vector<Group_Params>& params) {
   // first filter out any groups we don't have a name for:
   std::vector<std::string> names;
   for(auto p : params) {
      if(auto name = p.to_string()) {
         names.push_back(name.value());
      }
   }

   o << key << " = ";

   for(size_t i = 0; i != names.size(); ++i) {
      o << names[i];
      if(i != names.size() - 1) {
         o << " ";
      }
   }
   o << "\n";
}

void print_vec(std::ostream& o, const char* key, const std::vector<Certificate_Type>& types) {
   o << key << " = ";
   for(size_t i = 0; i != types.size(); ++i) {
      o << certificate_type_to_string(types[i]);
      if(i != types.size() - 1) {
         o << ' ';
      }
   }
   o << '\n';
}

void print_bool(std::ostream& o, const char* key, bool b) {
   o << key << " = " << (b ? "true" : "false") << '\n';
}

}  // namespace

void Policy::print(std::ostream& o) const {
   print_bool(o, "allow_tls12", allow_tls12());
   print_bool(o, "allow_tls13", allow_tls13());
   print_bool(o, "allow_dtls12", allow_dtls12());
   print_bool(o, "allow_ssl_key_log_file", allow_ssl_key_log_file());
   print_vec(o, "ciphers", allowed_ciphers());
   print_vec(o, "macs", allowed_macs());
   print_vec(o, "signature_hashes", allowed_signature_hashes());
   print_vec(o, "signature_methods", allowed_signature_methods());
   print_vec(o, "key_exchange_methods", allowed_key_exchange_methods());
   print_vec(o, "key_exchange_groups", key_exchange_groups());
   const auto groups_to_offer = key_exchange_groups_to_offer();
   if(groups_to_offer.empty()) {
      print_vec(o, "key_exchange_groups_to_offer", {std::string("none")});
   } else {
      print_vec(o, "key_exchange_groups_to_offer", groups_to_offer);
   }
   print_bool(o, "allow_insecure_renegotiation", allow_insecure_renegotiation());
   print_bool(o, "include_time_in_hello_random", include_time_in_hello_random());
   print_bool(o, "allow_server_initiated_renegotiation", allow_server_initiated_renegotiation());
   print_bool(o, "hide_unknown_users", hide_unknown_users());
   print_bool(o, "server_uses_own_ciphersuite_preferences", server_uses_own_ciphersuite_preferences());
   print_bool(o, "negotiate_encrypt_then_mac", negotiate_encrypt_then_mac());
   print_bool(o, "support_cert_status_message", support_cert_status_message());
   print_bool(o, "tls_13_middlebox_compatibility_mode", tls_13_middlebox_compatibility_mode());
   print_vec(o, "accepted_client_certificate_types", accepted_client_certificate_types());
   print_vec(o, "accepted_server_certificate_types", accepted_server_certificate_types());
   print_bool(o, "hash_hello_random", hash_hello_random());
   if(record_size_limit().has_value()) {
      o << "record_size_limit = " << record_size_limit().value() << '\n';
   }
   o << "maximum_session_tickets_per_client_hello = " << maximum_session_tickets_per_client_hello() << '\n';
   o << "session_ticket_lifetime = " << session_ticket_lifetime().count() << '\n';
   print_bool(o, "reuse_session_tickets", reuse_session_tickets());
   o << "new_session_tickets_upon_handshake_success = " << new_session_tickets_upon_handshake_success() << '\n';
   o << "minimum_dh_group_size = " << minimum_dh_group_size() << '\n';
   o << "minimum_ecdh_group_size = " << minimum_ecdh_group_size() << '\n';
   o << "minimum_rsa_bits = " << minimum_rsa_bits() << '\n';
   o << "minimum_signature_strength = " << minimum_signature_strength() << '\n';
}

std::string Policy::to_string() const {
   std::ostringstream oss;
   this->print(oss);
   return oss.str();
}

std::vector<std::string> Strict_Policy::allowed_ciphers() const {
   return {"ChaCha20Poly1305", "AES-256/GCM", "AES-128/GCM"};
}

std::vector<std::string> Strict_Policy::allowed_signature_hashes() const {
   return {"SHA-512", "SHA-384"};
}

std::vector<std::string> Strict_Policy::allowed_macs() const {
   return {"AEAD"};
}

std::vector<std::string> Strict_Policy::allowed_key_exchange_methods() const {
   return {"ECDH"};
}

}  // namespace Botan::TLS
