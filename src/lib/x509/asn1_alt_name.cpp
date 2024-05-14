/*
* AlternativeName
* (C) 1999-2007 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <sstream>

namespace Botan {

/*
* Create an AlternativeName
*/
AlternativeName::AlternativeName(std::string_view email_addr,
                                 std::string_view uri,
                                 std::string_view dns,
                                 std::string_view ip) {
   if(!email_addr.empty()) {
      add_email(email_addr);
   }
   if(!dns.empty()) {
      add_dns(dns);
   }
   if(!uri.empty()) {
      add_uri(uri);
   }
   if(!ip.empty()) {
      if(auto ipv4 = string_to_ipv4(ip)) {
         add_ipv4_address(*ipv4);
      } else {
         throw Invalid_Argument(fmt("Invalid IPv4 address '{}'", ip));
      }
   }
}

/*
* Add an attribute to an alternative name
*/
void AlternativeName::add_attribute(std::string_view type, std::string_view value) {
   if(type.empty() || value.empty()) {
      return;
   }

   if(type == "DNS") {
      this->add_dns(value);
   } else if(type == "RFC822") {
      this->add_email(value);
   } else if(type == "URI") {
      this->add_uri(value);
   } else if(type == "DN") {
      X509_DN dn;
      std::istringstream ss{std::string(value)};
      ss >> dn;
      this->add_dn(dn);
   } else if(type == "IP") {
      if(auto ipv4 = string_to_ipv4(value)) {
         add_ipv4_address(*ipv4);
      } else {
         throw Invalid_Argument(fmt("Invalid IPv4 address '{}'", value));
      }
   } else {
      throw Not_Implemented(fmt("Unknown AlternativeName name type {}", type));
   }
}

/*
* Add an OtherName field
*/
void AlternativeName::add_othername(const OID& oid, std::string_view value, ASN1_Type type) {
   if(value.empty()) {
      return;
   }
   this->add_other_name(oid, ASN1_String(value, type));
}

/*
* Return all of the alternative names
*/
std::multimap<std::string, std::string> AlternativeName::contents() const {
   std::multimap<std::string, std::string> names;

   for(const auto& nm : this->dns()) {
      names.emplace("DNS", nm);
   }

   for(const auto& nm : this->email()) {
      names.emplace("RFC822", nm);
   }

   for(const auto& nm : this->uris()) {
      names.emplace("URI", nm);
   }

   for(uint32_t ipv4 : this->ipv4_address()) {
      names.emplace("IP", ipv4_to_string(ipv4));
   }

   for(const auto& nm : this->directory_names()) {
      names.emplace("DN", nm.to_string());
   }

   for(const auto& othername : this->other_names()) {
      names.emplace(othername.first.to_formatted_string(), othername.second.value());
   }

   return names;
}

std::multimap<std::string, std::string, std::less<>> AlternativeName::get_attributes() const {
   std::multimap<std::string, std::string, std::less<>> r;

   for(const auto& c : this->contents()) {
      r.emplace(c.first, c.second);
   }

   return r;
}

bool AlternativeName::has_field(std::string_view attr) const {
   return !this->get_attribute(attr).empty();
}

std::string AlternativeName::get_first_attribute(std::string_view type) const {
   auto attr = this->get_attribute(type);

   if(!attr.empty()) {
      return attr[0];
   }

   return "";
}

std::vector<std::string> AlternativeName::get_attribute(std::string_view attr) const {
   auto set_to_vector = [](const std::set<std::string>& s) -> std::vector<std::string> { return {s.begin(), s.end()}; };

   if(attr == "DNS") {
      return set_to_vector(this->dns());
   } else if(attr == "RFC822") {
      return set_to_vector(this->email());
   } else if(attr == "URI") {
      return set_to_vector(this->uris());
   } else if(attr == "DN") {
      std::vector<std::string> ret;

      for(const auto& nm : this->directory_names()) {
         ret.push_back(nm.to_string());
      }

      return ret;
   } else if(attr == "IP") {
      std::vector<std::string> ip_str;
      for(uint32_t ipv4 : this->ipv4_address()) {
         ip_str.push_back(ipv4_to_string(ipv4));
      }
      return ip_str;
   } else {
      return {};
   }
}

X509_DN AlternativeName::dn() const {
   // This logic really does not make any sense, but it is
   // how this function was historically implemented.

   X509_DN combined_dn;

   for(const auto& dn : this->directory_names()) {
      std::ostringstream oss;
      oss << dn;

      std::istringstream iss(oss.str());
      iss >> combined_dn;
   }

   return combined_dn;
}

/*
* Return if this object has anything useful
*/
}  // namespace Botan
