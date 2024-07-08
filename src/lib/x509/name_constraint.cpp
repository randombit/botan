/*
* X.509 Name Constraint
* (C) 2015 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>
#include <botan/ber_dec.h>
#include <botan/loadstor.h>
#include <botan/x509cert.h>
#include <botan/parsing.h>
#include <sstream>

namespace Botan {

class DER_Encoder;

GeneralName::GeneralName(const std::string& str) : GeneralName()
   {
   size_t p = str.find(':');

   if(p != std::string::npos)
      {
      m_type = str.substr(0, p);
      m_name = str.substr(p + 1, std::string::npos);
      }
   else
      {
      throw Invalid_Argument("Failed to decode Name Constraint");
      }
   }

void GeneralName::encode_into(DER_Encoder&) const
   {
   throw Not_Implemented("GeneralName encoding");
   }

void GeneralName::decode_from(class BER_Decoder& ber)
   {
   BER_Object obj = ber.get_next_object();

   if(obj.is_a(1, CONTEXT_SPECIFIC))
      {
      m_type = "RFC822";
      m_name = ASN1::to_string(obj);
      }
   else if(obj.is_a(2, CONTEXT_SPECIFIC))
      {
      m_type = "DNS";
      m_name = ASN1::to_string(obj);
      }
   else if(obj.is_a(6, CONTEXT_SPECIFIC))
      {
      m_type = "URI";
      m_name = ASN1::to_string(obj);
      }
   else if(obj.is_a(4, ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED)))
      {
      m_type = "DN";
      X509_DN dn;
      BER_Decoder dec(obj);
      std::stringstream ss;

      dn.decode_from(dec);
      ss << dn;

      m_name = ss.str();
      }
   else if(obj.is_a(7, CONTEXT_SPECIFIC))
      {
      if(obj.length() == 8)
         {
         m_type = "IP";
         m_name = ipv4_to_string(load_be<uint32_t>(obj.bits(), 0)) + "/" +
                  ipv4_to_string(load_be<uint32_t>(obj.bits(), 1));
         }
      else if(obj.length() == 32)
         {
         throw Decoding_Error("Unsupported IPv6 name constraint");
         }
      else
         {
         throw Decoding_Error("Invalid IP name constraint size " + std::to_string(obj.length()));
         }
      }
   else
      {
      throw Decoding_Error("Found unknown GeneralName type");
      }
   }

GeneralName::MatchResult GeneralName::matches(const X509_Certificate& cert) const
   {
   std::vector<std::string> nam;
   std::function<bool(const GeneralName*, const std::string&)> match_fn;

   const X509_DN& dn = cert.subject_dn();
   const AlternativeName& alt_name = cert.subject_alt_name();

   if(type() == "DNS")
      {
      match_fn = std::mem_fn(&GeneralName::matches_dns);

      nam = alt_name.get_attribute("DNS");

      if(nam.empty())
         {
         nam = dn.get_attribute("CN");
         }
      }
   else if(type() == "DN")
      {
      match_fn = std::mem_fn(&GeneralName::matches_dn);

      nam.push_back(dn.to_string());

      const auto alt_dn = alt_name.dn();
      if(alt_dn.empty() == false)
         {
         nam.push_back(alt_dn.to_string());
         }
      }
   else if(type() == "IP")
      {
      match_fn = std::mem_fn(&GeneralName::matches_ip);
      nam = alt_name.get_attribute("IP");
      }
   else
      {
      return MatchResult::UnknownType;
      }

   if(nam.empty())
      {
      return MatchResult::NotFound;
      }

   bool some = false;
   bool all = true;

   for(const std::string& n: nam)
      {
      bool m = match_fn(this, n);

      some |= m;
      all &= m;
      }

   if(all)
      {
      return MatchResult::All;
      }
   else if(some)
      {
      return MatchResult::Some;
      }
   else
      {
      return MatchResult::None;
      }
   }

bool GeneralName::matches_dns(const std::string& nam) const
   {
   const std::string constraint = tolower_string(name());
   const std::string issued = tolower_string(nam);

   if(nam.size() == constraint.size())
      {
      return issued == constraint;
      }
   else if(constraint.size() > nam.size())
      {
      // The constraint is longer than the issued name: not possibly a match
      return false;
      }
   else
      {
      if(constraint.empty()) {
         return true;
      }

      std::string substr = issued.substr(nam.size() - constraint.size(), constraint.size());

      if(constraint.front() == '.') {
         return substr == constraint;
      } else if(substr[0] == '.') {
         return substr.substr(1) == constraint;
      } else {
         return substr == constraint && issued[issued.size() - constraint.size() - 1] == '.';
      }
   }
}

bool GeneralName::matches_dn(const std::string& nam) const
   {
   std::stringstream ss(nam);
   X509_DN nam_dn;
   ss >> nam_dn;
   return matches_dn_obj(nam_dn);
   }

bool GeneralName::matches_dn_obj(const X509_DN& nam_dn) const
   {
   std::stringstream tt(name());
   X509_DN my_dn;
   tt >> my_dn;

   auto attr = nam_dn.get_attributes();
   bool ret = true;
   size_t trys = 0;

   for(const auto& c: my_dn.dn_info())
      {
      auto i = attr.equal_range(c.first);

      if(i.first != i.second)
         {
         trys += 1;
         ret = ret && (i.first->second == c.second.value());
         }
      }

   return trys > 0 && ret;
   }

bool GeneralName::matches_ip(const std::string& nam) const
   {
   uint32_t ip = string_to_ipv4(nam);
   std::vector<std::string> p = split_on(name(), '/');

   if(p.size() != 2)
      throw Decoding_Error("failed to parse IPv4 address");

   uint32_t net = string_to_ipv4(p.at(0));
   uint32_t mask = string_to_ipv4(p.at(1));

   return (ip & mask) == net;
   }

std::ostream& operator<<(std::ostream& os, const GeneralName& gn)
   {
   os << gn.type() << ":" << gn.name();
   return os;
   }

GeneralSubtree::GeneralSubtree(const std::string& str) : GeneralSubtree()
   {
   size_t p0, p1;
   const auto min = std::stoull(str, &p0, 10);
   const auto max = std::stoull(str.substr(p0 + 1), &p1, 10);
   GeneralName gn(str.substr(p0 + p1 + 2));

   if(p0 > 0 && p1 > 0)
      {
      m_minimum = static_cast<size_t>(min);
      m_maximum = static_cast<size_t>(max);
      m_base = gn;
      }
   else
      {
      throw Invalid_Argument("Failed to decode Name Constraint");
      }
   }

void GeneralSubtree::encode_into(DER_Encoder&) const
   {
   throw Not_Implemented("General Subtree encoding");
   }

void GeneralSubtree::decode_from(class BER_Decoder& ber)
   {
   ber.start_cons(SEQUENCE)
      .decode(m_base)
      .decode_optional(m_minimum,ASN1_Tag(0), CONTEXT_SPECIFIC,size_t(0))
   .end_cons();

   if(m_minimum != 0)
     throw Decoding_Error("GeneralSubtree minimum must be 0");

   m_maximum = std::numeric_limits<std::size_t>::max();
   }

std::ostream& operator<<(std::ostream& os, const GeneralSubtree& gs)
   {
   os << gs.minimum() << "," << gs.maximum() << "," << gs.base();
   return os;
   }

NameConstraints::NameConstraints(std::vector<GeneralSubtree>&& permitted_subtrees,
                                 std::vector<GeneralSubtree>&& excluded_subtrees) :
   m_permitted_subtrees(permitted_subtrees), m_excluded_subtrees(excluded_subtrees)
   {
   for(const auto& c : m_permitted_subtrees)
      {
      m_permitted_name_types.insert(c.base().type());
      }
   for(const auto& c : m_excluded_subtrees)
      {
      m_excluded_name_types.insert(c.base().type());
      }
   }

namespace {

bool looks_like_ipv4(const std::string& s)
   {
   try
     {
     // ignores return value
     string_to_ipv4(s);
     return true;
     }
   catch(...)
      {
      return false;
      }
   }

}

bool NameConstraints::is_permitted(const X509_Certificate& cert, bool reject_unknown) const {
   if(permitted().empty()) {
      return true;
   }

   const auto& alt_name = cert.subject_alt_name();

   if(reject_unknown) {
      if(m_permitted_name_types.find("URI") != m_permitted_name_types.end() && !alt_name.get_attribute("URI").empty()) {
         return false;
      }
      if(m_permitted_name_types.find("RFC822") != m_permitted_name_types.end() && !alt_name.get_attribute("RFC822").empty()) {
         return false;
      }
   }

   auto is_permitted_dn = [&](const X509_DN& dn) {
      // If no restrictions, then immediate accept
      if(m_permitted_name_types.find("DN") == m_permitted_name_types.end()) {
         return true;
      }

      if(dn.empty()) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().type() == "DN" && c.base().matches_dn_obj(dn)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   auto is_permitted_dns_name = [&](const std::string& name) {
      if(name.empty() || name[0] == '.') {
         return false;
      }

      // If no restrictions, then immediate accept
      if(m_permitted_name_types.find("DNS") == m_permitted_name_types.end()) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().type() == "DNS" && c.base().matches_dns(name)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   auto is_permitted_ipv4 = [&](const std::string& ipv4) {
      // If no restrictions, then immediate accept
      if(m_permitted_name_types.find("IP") == m_permitted_name_types.end()) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().type() == "IP" && c.base().matches_ip(ipv4)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   if(!is_permitted_dn(cert.subject_dn())) {
      return false;
   }

   if(!is_permitted_dn(alt_name.dn()))
      {
      return false;
      }

   for(const auto& alt_dns : alt_name.get_attribute("DNS")) {
      if(!is_permitted_dns_name(alt_dns)) {
         return false;
      }
   }

   for(const auto& alt_ipv4 : alt_name.get_attribute("IP")) {
      if(!is_permitted_ipv4(alt_ipv4)) {
         return false;
      }
   }

   if(!alt_name.has_items())
      {
      for(const auto& cn : cert.subject_info("Name"))
         {
         if(cn.find(".") != std::string::npos)
            {
            if(looks_like_ipv4(cn))
               {
               if(!is_permitted_ipv4(cn))
                  {
                  return false;
                  }
               }
            else
               {
               if(!is_permitted_dns_name(cn))
                  {
                  return false;
                  }
               }
            }
         }
      }

   // We didn't encounter a name that doesn't have a matching constraint
   return true;
}

bool NameConstraints::is_excluded(const X509_Certificate& cert, bool reject_unknown) const {
   if(excluded().empty()) {
      return false;
   }

   const auto& alt_name = cert.subject_alt_name();

   if(reject_unknown) {
      if(m_excluded_name_types.find("URI") != m_excluded_name_types.end() && !alt_name.get_attribute("URI").empty()) {
         return false;
      }
      if(m_excluded_name_types.find("RFC822") != m_excluded_name_types.end() && !alt_name.get_attribute("RFC822").empty()) {
         return false;
      }
   }

   auto is_excluded_dn = [&](const X509_DN& dn) {
      // If no restrictions, then immediate accept
      if(m_excluded_name_types.find("DN") == m_excluded_name_types.end()) {
         return false;
      }

      if(dn.empty()) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().type() == "DN" && c.base().matches_dn_obj(dn)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   auto is_excluded_dns_name = [&](const std::string& name) {
      if(name.empty() || name[0] == '.') {
         return true;
      }

      // If no restrictions, then immediate accept
      if(m_excluded_name_types.find("DNS") == m_excluded_name_types.end()) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().type() == "DNS" && c.base().matches_dns(name)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   auto is_excluded_ipv4 = [&](const std::string& ipv4) {
      // If no restrictions, then immediate accept
      if(m_excluded_name_types.find("IP") == m_excluded_name_types.end()) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().type() == "IP" && c.base().matches_ip(ipv4)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   if(is_excluded_dn(cert.subject_dn())) {
      return true;
   }

   if(is_excluded_dn(alt_name.dn())) {
      return true;
   }

   for(const auto& alt_dns : alt_name.get_attribute("DNS")) {
      if(is_excluded_dns_name(alt_dns)) {
         return true;
      }
   }

   for(const auto& alt_ipv4 : alt_name.get_attribute("IP")) {
      if(is_excluded_ipv4(alt_ipv4)) {
         return true;
      }
   }

   if(!alt_name.has_items())
      {
      for(const auto& cn : cert.subject_info("Name"))
         {
         if(cn.find(".") != std::string::npos)
            {
            if(looks_like_ipv4(cn))
               {
               if(is_excluded_ipv4(cn))
                  {
                  return true;
                  }
               }
            else
               {
               if(is_excluded_dns_name(cn))
                  {
                  return true;
                  }
               }
            }
         }
      }

   // We didn't encounter a name that matched any prohibited name
   return false;
}

}  // namespace Botan
