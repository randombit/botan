/*
* Text-Based TLS Policy
* (C) 2016,2017 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_policy.h>
#include <botan/exceptn.h>
#include <botan/parsing.h>
#include <sstream>

namespace Botan {

namespace TLS {

std::vector<std::string> Text_Policy::allowed_ciphers() const
   {
   return get_list("ciphers", Policy::allowed_ciphers());
   }

std::vector<std::string> Text_Policy::allowed_signature_hashes() const
   {
   return get_list("signature_hashes", Policy::allowed_signature_hashes());
   }

std::vector<std::string> Text_Policy::allowed_macs() const
   {
   return get_list("macs", Policy::allowed_macs());
   }

std::vector<std::string> Text_Policy::allowed_key_exchange_methods() const
   {
   return get_list("key_exchange_methods", Policy::allowed_key_exchange_methods());
   }

std::vector<std::string> Text_Policy::allowed_signature_methods() const
   {
   return get_list("signature_methods", Policy::allowed_signature_methods());
   }

bool Text_Policy::use_ecc_point_compression() const
   {
   return get_bool("use_ecc_point_compression", Policy::use_ecc_point_compression());
   }

bool Text_Policy::allow_tls10() const
   {
   return get_bool("allow_tls10", Policy::allow_tls10());
   }

bool Text_Policy::allow_tls11() const
   {
   return get_bool("allow_tls11", Policy::allow_tls11());
   }

bool Text_Policy::allow_tls12() const
   {
   return get_bool("allow_tls12", Policy::allow_tls12());
   }

bool Text_Policy::allow_dtls10() const
   {
   return get_bool("allow_dtls10", Policy::allow_dtls10());
   }

bool Text_Policy::allow_dtls12() const
   {
   return get_bool("allow_dtls12", Policy::allow_dtls12());
   }

bool Text_Policy::allow_insecure_renegotiation() const
   {
   return get_bool("allow_insecure_renegotiation", Policy::allow_insecure_renegotiation());
   }

bool Text_Policy::include_time_in_hello_random() const
   {
   return get_bool("include_time_in_hello_random", Policy::include_time_in_hello_random());
   }

bool Text_Policy::require_client_certificate_authentication() const
   {
   return get_bool("require_client_certificate_authentication", Policy::require_client_certificate_authentication());
   }

bool Text_Policy::allow_client_initiated_renegotiation() const
   {
   return get_bool("allow_client_initiated_renegotiation", Policy::allow_client_initiated_renegotiation());
   }

bool Text_Policy::allow_server_initiated_renegotiation() const
   {
   return get_bool("allow_server_initiated_renegotiation", Policy::allow_server_initiated_renegotiation());
   }

bool Text_Policy::server_uses_own_ciphersuite_preferences() const
   {
   return get_bool("server_uses_own_ciphersuite_preferences", Policy::server_uses_own_ciphersuite_preferences());
   }

bool Text_Policy::negotiate_encrypt_then_mac() const
   {
   return get_bool("negotiate_encrypt_then_mac", Policy::negotiate_encrypt_then_mac());
   }

bool Text_Policy::support_cert_status_message() const
   {
   return get_bool("support_cert_status_message", Policy::support_cert_status_message());
   }

std::vector<Group_Params> Text_Policy::key_exchange_groups() const
   {
   std::string group_str = get_str("key_exchange_groups");

   if(group_str.empty())
      {
      // fall back to previously used name
      group_str = get_str("groups");
      }

   if(group_str.empty())
      {
      return Policy::key_exchange_groups();
      }

   std::vector<Group_Params> groups;
   for(std::string group_name : split_on(group_str, ' '))
      {
      Group_Params group_id = group_param_from_string(group_name);

      if(group_id == Group_Params::NONE)
         {
         try
            {
            size_t consumed = 0;
            unsigned long ll_id = std::stoul(group_name, &consumed, 0);
            if(consumed != group_name.size())
               continue; // some other cruft

            const uint16_t id = static_cast<uint16_t>(ll_id);

            if(id != ll_id)
               continue; // integer too large

            group_id = static_cast<Group_Params>(id);
            }
         catch(...)
            {
            continue;
            }
         }

      if(group_id != Group_Params::NONE)
         groups.push_back(group_id);
      }

   return groups;
   }

size_t Text_Policy::minimum_ecdh_group_size() const
   {
   return get_len("minimum_ecdh_group_size", Policy::minimum_ecdh_group_size());
   }

size_t Text_Policy::minimum_ecdsa_group_size() const
   {
   return get_len("minimum_ecdsa_group_size", Policy::minimum_ecdsa_group_size());
   }

size_t Text_Policy::minimum_dh_group_size() const
   {
   return get_len("minimum_dh_group_size", Policy::minimum_dh_group_size());
   }

size_t Text_Policy::minimum_rsa_bits() const
   {
   return get_len("minimum_rsa_bits", Policy::minimum_rsa_bits());
   }

size_t Text_Policy::minimum_signature_strength() const
   {
   return get_len("minimum_signature_strength", Policy::minimum_signature_strength());
   }

size_t Text_Policy::dtls_default_mtu() const
   {
   return get_len("dtls_default_mtu", Policy::dtls_default_mtu());
   }

size_t Text_Policy::dtls_initial_timeout() const
   {
   return get_len("dtls_initial_timeout", Policy::dtls_initial_timeout());
   }

size_t Text_Policy::dtls_maximum_timeout() const
   {
   return get_len("dtls_maximum_timeout", Policy::dtls_maximum_timeout());
   }

bool Text_Policy::require_cert_revocation_info() const
   {
   return get_bool("require_cert_revocation_info", Policy::require_cert_revocation_info());
   }

bool Text_Policy::hide_unknown_users() const
   {
   return get_bool("hide_unknown_users", Policy::hide_unknown_users());
   }

uint32_t Text_Policy::session_ticket_lifetime() const
   {
   return static_cast<uint32_t>(get_len("session_ticket_lifetime", Policy::session_ticket_lifetime()));
   }

bool Text_Policy::send_fallback_scsv(Protocol_Version version) const
   {
   return get_bool("send_fallback_scsv", false) ? Policy::send_fallback_scsv(version) : false;
   }

std::vector<uint16_t> Text_Policy::srtp_profiles() const
   {
   std::vector<uint16_t> r;
   for(std::string p : get_list("srtp_profiles", std::vector<std::string>()))
      {
      r.push_back(to_uint16(p));
      }
   return r;
   }

void Text_Policy::set(const std::string& k, const std::string& v)
   {
   m_kv[k] = v;
   }

Text_Policy::Text_Policy(const std::string& s)
   {
   std::istringstream iss(s);
   m_kv = read_cfg(iss);
   }

Text_Policy::Text_Policy(std::istream& in) : m_kv(read_cfg(in))
   {}

std::vector<std::string>
Text_Policy::get_list(const std::string& key,
                      const std::vector<std::string>& def) const
   {
   const std::string v = get_str(key);

   if(v.empty())
      {
      return def;
      }

   return split_on(v, ' ');
   }

size_t Text_Policy::get_len(const std::string& key, size_t def) const
   {
   const std::string v = get_str(key);

   if(v.empty())
      {
      return def;
      }

   return to_u32bit(v);
   }

bool Text_Policy::get_bool(const std::string& key, bool def) const
   {
   const std::string v = get_str(key);

   if(v.empty())
      {
      return def;
      }

   if(v == "true" || v == "True")
      {
      return true;
      }
   else if(v == "false" || v == "False")
      {
      return false;
      }
   else
      {
      throw Decoding_Error("Invalid boolean '" + v + "'");
      }
   }

std::string Text_Policy::get_str(const std::string& key, const std::string& def) const
   {
   auto i = m_kv.find(key);
   if(i == m_kv.end())
      {
      return def;
      }

   return i->second;
   }

bool Text_Policy::set_value(const std::string& key, const std::string& val, bool overwrite)
   {
   auto i = m_kv.find(key);

   if(overwrite == false && i != m_kv.end())
      return false;

   m_kv.insert(i, std::make_pair(key, val));
   return true;
   }

}

}
