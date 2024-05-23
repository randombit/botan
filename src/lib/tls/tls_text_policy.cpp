/*
* Text-Based TLS Policy
* (C) 2016,2017 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_policy.h>

#include <botan/exceptn.h>
#include <botan/internal/parsing.h>
#include <optional>
#include <sstream>

namespace Botan::TLS {

bool Text_Policy::allow_ssl_key_log_file() const {
   return get_bool("allow_ssl_key_log_file", Policy::allow_ssl_key_log_file());
}

std::vector<std::string> Text_Policy::allowed_ciphers() const {
   return get_list("ciphers", Policy::allowed_ciphers());
}

std::vector<std::string> Text_Policy::allowed_signature_hashes() const {
   return get_list("signature_hashes", Policy::allowed_signature_hashes());
}

std::vector<std::string> Text_Policy::allowed_macs() const {
   return get_list("macs", Policy::allowed_macs());
}

std::vector<std::string> Text_Policy::allowed_key_exchange_methods() const {
   return get_list("key_exchange_methods", Policy::allowed_key_exchange_methods());
}

std::vector<std::string> Text_Policy::allowed_signature_methods() const {
   return get_list("signature_methods", Policy::allowed_signature_methods());
}

bool Text_Policy::use_ecc_point_compression() const {
   return get_bool("use_ecc_point_compression", Policy::use_ecc_point_compression());
}

bool Text_Policy::allow_tls12() const {
   return get_bool("allow_tls12", Policy::allow_tls12());
}

bool Text_Policy::allow_tls13() const {
   return get_bool("allow_tls13", Policy::allow_tls13());
}

bool Text_Policy::allow_dtls12() const {
   return get_bool("allow_dtls12", Policy::allow_dtls12());
}

bool Text_Policy::allow_insecure_renegotiation() const {
   return get_bool("allow_insecure_renegotiation", Policy::allow_insecure_renegotiation());
}

bool Text_Policy::include_time_in_hello_random() const {
   return get_bool("include_time_in_hello_random", Policy::include_time_in_hello_random());
}

bool Text_Policy::require_client_certificate_authentication() const {
   return get_bool("require_client_certificate_authentication", Policy::require_client_certificate_authentication());
}

bool Text_Policy::allow_client_initiated_renegotiation() const {
   return get_bool("allow_client_initiated_renegotiation", Policy::allow_client_initiated_renegotiation());
}

std::vector<Certificate_Type> Text_Policy::accepted_client_certificate_types() const {
   const auto cert_types = get_str("accepted_client_certificate_types");
   return (cert_types.empty()) ? Policy::accepted_client_certificate_types() : read_cert_type_list(cert_types);
}

std::vector<Certificate_Type> Text_Policy::accepted_server_certificate_types() const {
   const auto cert_types = get_str("accepted_server_certificate_types");
   return (cert_types.empty()) ? Policy::accepted_server_certificate_types() : read_cert_type_list(cert_types);
}

bool Text_Policy::allow_server_initiated_renegotiation() const {
   return get_bool("allow_server_initiated_renegotiation", Policy::allow_server_initiated_renegotiation());
}

bool Text_Policy::server_uses_own_ciphersuite_preferences() const {
   return get_bool("server_uses_own_ciphersuite_preferences", Policy::server_uses_own_ciphersuite_preferences());
}

bool Text_Policy::negotiate_encrypt_then_mac() const {
   return get_bool("negotiate_encrypt_then_mac", Policy::negotiate_encrypt_then_mac());
}

std::optional<uint16_t> Text_Policy::record_size_limit() const {
   const auto limit = get_len("record_size_limit", 0);
   // RFC 8449 4.
   //    TLS 1.3 uses a limit of 2^14+1 octets.
   BOTAN_ARG_CHECK(limit <= 16385, "record size limit too large");
   return (limit > 0) ? std::make_optional(static_cast<uint16_t>(limit)) : std::nullopt;
}

bool Text_Policy::support_cert_status_message() const {
   return get_bool("support_cert_status_message", Policy::support_cert_status_message());
}

std::vector<Group_Params> Text_Policy::key_exchange_groups() const {
   std::string group_str = get_str("key_exchange_groups");

   if(group_str.empty()) {
      // fall back to previously used name
      group_str = get_str("groups");
   }

   if(group_str.empty()) {
      return Policy::key_exchange_groups();
   }

   return read_group_list(group_str);
}

std::vector<Group_Params> Text_Policy::key_exchange_groups_to_offer() const {
   std::string group_str = get_str("key_exchange_groups_to_offer", "notset");

   if(group_str.empty() || group_str == "notset") {
      // policy was not set, fall back to default behaviour
      return Policy::key_exchange_groups_to_offer();
   }

   if(group_str == "none") {
      return {};
   }

   return read_group_list(group_str);
}

size_t Text_Policy::minimum_ecdh_group_size() const {
   return get_len("minimum_ecdh_group_size", Policy::minimum_ecdh_group_size());
}

size_t Text_Policy::minimum_ecdsa_group_size() const {
   return get_len("minimum_ecdsa_group_size", Policy::minimum_ecdsa_group_size());
}

size_t Text_Policy::minimum_dh_group_size() const {
   return get_len("minimum_dh_group_size", Policy::minimum_dh_group_size());
}

size_t Text_Policy::minimum_rsa_bits() const {
   return get_len("minimum_rsa_bits", Policy::minimum_rsa_bits());
}

size_t Text_Policy::minimum_signature_strength() const {
   return get_len("minimum_signature_strength", Policy::minimum_signature_strength());
}

size_t Text_Policy::dtls_default_mtu() const {
   return get_len("dtls_default_mtu", Policy::dtls_default_mtu());
}

size_t Text_Policy::dtls_initial_timeout() const {
   return get_len("dtls_initial_timeout", Policy::dtls_initial_timeout());
}

size_t Text_Policy::dtls_maximum_timeout() const {
   return get_len("dtls_maximum_timeout", Policy::dtls_maximum_timeout());
}

bool Text_Policy::require_cert_revocation_info() const {
   return get_bool("require_cert_revocation_info", Policy::require_cert_revocation_info());
}

bool Text_Policy::hide_unknown_users() const {
   return get_bool("hide_unknown_users", Policy::hide_unknown_users());
}

size_t Text_Policy::maximum_session_tickets_per_client_hello() const {
   return get_len("maximum_session_tickets_per_client_hello", Policy::maximum_session_tickets_per_client_hello());
}

std::chrono::seconds Text_Policy::session_ticket_lifetime() const {
   return get_duration("session_ticket_lifetime", Policy::session_ticket_lifetime());
}

bool Text_Policy::reuse_session_tickets() const {
   return get_bool("reuse_session_tickets", Policy::reuse_session_tickets());
}

size_t Text_Policy::new_session_tickets_upon_handshake_success() const {
   return get_len("new_session_tickets_upon_handshake_success", Policy::new_session_tickets_upon_handshake_success());
}

std::vector<uint16_t> Text_Policy::srtp_profiles() const {
   std::vector<uint16_t> r;
   for(const auto& p : get_list("srtp_profiles", std::vector<std::string>())) {
      r.push_back(to_uint16(p));
   }
   return r;
}

bool Text_Policy::tls_13_middlebox_compatibility_mode() const {
   return get_bool("tls_13_middlebox_compatibility_mode", Policy::tls_13_middlebox_compatibility_mode());
}

bool Text_Policy::hash_hello_random() const {
   return get_bool("hash_hello_random", Policy::hash_hello_random());
}

void Text_Policy::set(const std::string& key, const std::string& value) {
   m_kv[key] = value;
}

Text_Policy::Text_Policy(std::string_view s) {
   std::istringstream iss{std::string(s)};  // FIXME C++23 avoid copy
   m_kv = read_cfg(iss);
}

Text_Policy::Text_Policy(std::istream& in) : m_kv(read_cfg(in)) {}

std::vector<std::string> Text_Policy::get_list(const std::string& key, const std::vector<std::string>& def) const {
   const std::string v = get_str(key);

   if(v.empty()) {
      return def;
   }

   return split_on(v, ' ');
}

std::vector<Group_Params> Text_Policy::read_group_list(std::string_view group_str) const {
   std::vector<Group_Params> groups;
   for(const auto& group_name : split_on(group_str, ' ')) {
      Group_Params group_id = Group_Params::from_string(group_name).value_or(Group_Params::NONE);

#if !defined(BOTAN_HAS_X25519)
      if(group_id == Group_Params::X25519)
         continue;
#endif
#if !defined(BOTAN_HAS_X448)
      if(group_id == Group_Params::X448)
         continue;
#endif

      if(group_id == Group_Params::NONE) {
         try {
            size_t consumed = 0;
            unsigned long ll_id = std::stoul(group_name, &consumed, 0);
            if(consumed != group_name.size()) {
               continue;  // some other cruft
            }

            const uint16_t id = static_cast<uint16_t>(ll_id);

            if(id != ll_id) {
               continue;  // integer too large
            }

            group_id = static_cast<Group_Params>(id);
         } catch(...) {
            continue;
         }
      }

      if(group_id != Group_Params::NONE) {
         groups.push_back(group_id);
      }
   }

   return groups;
}

std::vector<Certificate_Type> Text_Policy::read_cert_type_list(const std::string& cert_type_names) const {
   std::vector<Certificate_Type> cert_types;
   for(const std::string& cert_type_name : split_on(cert_type_names, ' ')) {
      cert_types.push_back(certificate_type_from_string(cert_type_name));
   }

   return cert_types;
}

size_t Text_Policy::get_len(const std::string& key, size_t def) const {
   const std::string v = get_str(key);

   if(v.empty()) {
      return def;
   }

   return to_u32bit(v);
}

std::chrono::seconds Text_Policy::get_duration(const std::string& key, std::chrono::seconds def) const {
   using rep_t = std::chrono::seconds::rep;
   constexpr rep_t max_seconds = std::chrono::seconds::max().count();
   constexpr auto max_sizet = std::numeric_limits<size_t>::max();
   using ull = unsigned long long;

   // The concrete type of `rep` is not specified exactly. Let's play it extra safe...
   // e.g. on 32-bit platforms size_t is 32 bits but rep_t is "at least 35 bits"

   // at least zero and certainly fitting into rep_t
   const rep_t positive_default = std::max(def.count(), rep_t(0));
   // at least zero but capped to whatever size_t can handle
   const size_t positive_capped_default = static_cast<size_t>(std::min<ull>(positive_default, max_sizet));
   // at least zero but capped to whatever rep_t can handle
   const rep_t result = static_cast<rep_t>(std::min<ull>(get_len(key, positive_capped_default), max_seconds));

   return std::chrono::seconds(result);
}

bool Text_Policy::get_bool(const std::string& key, bool def) const {
   const std::string v = get_str(key);

   if(v.empty()) {
      return def;
   }

   if(v == "true" || v == "True") {
      return true;
   } else if(v == "false" || v == "False") {
      return false;
   } else {
      throw Decoding_Error("Invalid boolean '" + v + "'");
   }
}

std::string Text_Policy::get_str(const std::string& key, const std::string& def) const {
   auto i = m_kv.find(key);
   if(i == m_kv.end()) {
      return def;
   }

   return i->second;
}

bool Text_Policy::set_value(const std::string& key, std::string_view val, bool overwrite) {
   auto i = m_kv.find(key);

   if(overwrite == false && i != m_kv.end()) {
      return false;
   }

   m_kv.insert(i, std::make_pair(key, val));
   return true;
}

}  // namespace Botan::TLS
