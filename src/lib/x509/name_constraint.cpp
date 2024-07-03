/*
* X.509 Name Constraint
* (C) 2015 Kai Michaelis
*     2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/ber_dec.h>
#include <botan/x509cert.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <functional>
#include <sstream>

namespace Botan {

class DER_Encoder;

std::string GeneralName::type() const {
   switch(m_type) {
      case NameType::Unknown:
         throw Encoding_Error("Could not convert unknown NameType to string");
      case NameType::RFC822:
         return "RFC822";
      case NameType::DNS:
         return "DNS";
      case NameType::URI:
         return "URI";
      case NameType::DN:
         return "DN";
      case NameType::IPv4:
         return "IP";
      case NameType::Other:
         return "Other";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

std::string GeneralName::name() const {
   const size_t index = m_name.index();

   if(index == RFC822_IDX) {
      return std::get<RFC822_IDX>(m_name);
   } else if(index == DNS_IDX) {
      return std::get<DNS_IDX>(m_name);
   } else if(index == URI_IDX) {
      return std::get<URI_IDX>(m_name);
   } else if(index == DN_IDX) {
      return std::get<DN_IDX>(m_name).to_string();
   } else if(index == IPV4_IDX) {
      auto [net, mask] = std::get<IPV4_IDX>(m_name);
      return fmt("{}/{}", ipv4_to_string(net), ipv4_to_string(mask));
   } else {
      BOTAN_ASSERT_UNREACHABLE();
   }
}

void GeneralName::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("GeneralName encoding");
}

void GeneralName::decode_from(BER_Decoder& ber) {
   BER_Object obj = ber.get_next_object();

   if(obj.is_a(0, ASN1_Class::ExplicitContextSpecific)) {
      m_type = NameType::Other;
   } else if(obj.is_a(1, ASN1_Class::ContextSpecific)) {
      m_type = NameType::RFC822;
      m_name.emplace<RFC822_IDX>(ASN1::to_string(obj));
   } else if(obj.is_a(2, ASN1_Class::ContextSpecific)) {
      m_type = NameType::DNS;
      // Store it in case insensitive form so we don't have to do it
      // again while matching
      m_name.emplace<DNS_IDX>(tolower_string(ASN1::to_string(obj)));
   } else if(obj.is_a(6, ASN1_Class::ContextSpecific)) {
      m_type = NameType::URI;
      m_name.emplace<URI_IDX>(ASN1::to_string(obj));
   } else if(obj.is_a(4, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      X509_DN dn;
      BER_Decoder dec(obj);
      dn.decode_from(dec);
      m_type = NameType::DN;
      m_name.emplace<DN_IDX>(dn);
   } else if(obj.is_a(7, ASN1_Class::ContextSpecific)) {
      if(obj.length() == 8) {
         const uint32_t net = load_be<uint32_t>(obj.bits(), 0);
         const uint32_t mask = load_be<uint32_t>(obj.bits(), 1);

         m_type = NameType::IPv4;
         m_name.emplace<IPV4_IDX>(std::make_pair(net, mask));
      } else if(obj.length() == 32) {
         // IPv6 name constraints are not implemented
         m_type = NameType::Unknown;
      } else {
         throw Decoding_Error("Invalid IP name constraint size " + std::to_string(obj.length()));
      }
   } else {
      m_type = NameType::Unknown;
   }
}

bool GeneralName::matches_dns(const std::string& dns_name) const {
   if(m_type == NameType::DNS) {
      const auto& constraint = std::get<DNS_IDX>(m_name);
      return matches_dns(dns_name, constraint);
   }
   return false;
}

bool GeneralName::matches_ipv4(uint32_t ip) const {
   if(m_type == NameType::IPv4) {
      auto [net, mask] = std::get<IPV4_IDX>(m_name);
      return (ip & mask) == net;
   }
   return false;
}

bool GeneralName::matches_dn(const X509_DN& dn) const {
   if(m_type == NameType::DN) {
      const X509_DN& constraint = std::get<DN_IDX>(m_name);
      return matches_dn(dn, constraint);
   }
   return false;
}

GeneralName::MatchResult GeneralName::matches(const X509_Certificate& cert) const {
   class MatchScore final {
      public:
         MatchScore() : m_any(false), m_some(false), m_all(true) {}

         void add(bool m) {
            m_any = true;
            m_some |= m;
            m_all &= m;
         }

         MatchResult result() const {
            if(!m_any) {
               return MatchResult::NotFound;
            } else if(m_all) {
               return MatchResult::All;
            } else if(m_some) {
               return MatchResult::Some;
            } else {
               return MatchResult::None;
            }
         }

      private:
         bool m_any;
         bool m_some;
         bool m_all;
   };

   const X509_DN& dn = cert.subject_dn();
   const AlternativeName& alt_name = cert.subject_alt_name();

   MatchScore score;

   if(m_type == NameType::DNS) {
      const auto& constraint = std::get<DNS_IDX>(m_name);

      const auto& alt_names = alt_name.dns();

      for(const std::string& dns : alt_names) {
         score.add(matches_dns(dns, constraint));
      }

      if(alt_name.count() == 0) {
         // Check CN instead...
         for(const std::string& cn : dn.get_attribute("CN")) {
            if(!string_to_ipv4(cn).has_value()) {
               score.add(matches_dns(cn, constraint));
            }
         }
      }
   } else if(m_type == NameType::DN) {
      const X509_DN& constraint = std::get<DN_IDX>(m_name);
      score.add(matches_dn(dn, constraint));

      for(const auto& alt_dn : alt_name.directory_names()) {
         score.add(matches_dn(alt_dn, constraint));
      }
   } else if(m_type == NameType::IPv4) {
      auto [net, mask] = std::get<IPV4_IDX>(m_name);

      if(alt_name.count() == 0) {
         // Check CN instead...
         for(const std::string& cn : dn.get_attribute("CN")) {
            if(auto ipv4 = string_to_ipv4(cn)) {
               bool match = (ipv4.value() & mask) == net;
               score.add(match);
            }
         }
      } else {
         for(uint32_t ipv4 : alt_name.ipv4_address()) {
            bool match = (ipv4 & mask) == net;
            score.add(match);
         }
      }
   } else {
      // URI and email name constraint matching not implemented
      return MatchResult::UnknownType;
   }

   return score.result();
}

//static
bool GeneralName::matches_dns(std::string_view name, std::string_view constraint) {
   // both constraint and name are assumed already tolower
   if(name.size() == constraint.size()) {
      return name == constraint;
   } else if(constraint.size() > name.size()) {
      // The constraint is longer than the issued name: not possibly a match
      return false;
   } else {
      BOTAN_ASSERT_NOMSG(name.size() > constraint.size());

      if(constraint.empty()) {
         return true;
      }

      std::string_view substr = name.substr(name.size() - constraint.size(), constraint.size());

      if(constraint.front() == '.') {
         return substr == constraint;
      } else if(substr[0] == '.') {
         return substr.substr(1) == constraint;
      } else {
         return substr == constraint && name[name.size() - constraint.size() - 1] == '.';
      }
   }
}

//static
bool GeneralName::matches_dn(const X509_DN& name, const X509_DN& constraint) {
   const auto attr = name.get_attributes();
   bool ret = true;
   size_t trys = 0;

   for(const auto& c : constraint.dn_info()) {
      auto i = attr.equal_range(c.first);

      if(i.first != i.second) {
         trys += 1;
         ret = ret && (i.first->second == c.second.value());
      }
   }

   return trys > 0 && ret;
}

std::ostream& operator<<(std::ostream& os, const GeneralName& gn) {
   os << gn.type() << ":" << gn.name();
   return os;
}

GeneralSubtree::GeneralSubtree() : m_base() {}

void GeneralSubtree::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("GeneralSubtree encoding");
}

void GeneralSubtree::decode_from(BER_Decoder& ber) {
   size_t minimum;

   ber.start_sequence()
      .decode(m_base)
      .decode_optional(minimum, ASN1_Type(0), ASN1_Class::ContextSpecific, size_t(0))
      .end_cons();

   if(minimum != 0) {
      throw Decoding_Error("GeneralSubtree minimum must be 0");
   }
}

std::ostream& operator<<(std::ostream& os, const GeneralSubtree& gs) {
   os << gs.base();
   return os;
}

NameConstraints::NameConstraints(std::vector<GeneralSubtree>&& permitted_subtrees,
                                 std::vector<GeneralSubtree>&& excluded_subtrees) :
      m_permitted_subtrees(std::move(permitted_subtrees)), m_excluded_subtrees(std::move(excluded_subtrees)) {
   for(const auto& c : m_permitted_subtrees) {
      m_permitted_name_types.insert(c.base().type_code());
   }
   for(const auto& c : m_excluded_subtrees) {
      m_excluded_name_types.insert(c.base().type_code());
   }
}

namespace {

bool exceeds_limit(size_t dn_count, size_t alt_count, size_t constraint_count) {
   /**
   * OpenSSL uses a similar limit, but applies it to the total number of
   * constraints, while we apply it to permitted and excluded independently.
   */
   constexpr size_t MAX_NC_CHECKS = (1 << 20);

   if(auto names = checked_add(dn_count, alt_count)) {
      if(auto product = checked_mul(*names, constraint_count)) {
         if(*product < MAX_NC_CHECKS) {
            return false;
         }
      }
   }
   return true;
}

}  // namespace

bool NameConstraints::is_permitted(const X509_Certificate& cert, bool reject_unknown) const {
   if(permitted().empty()) {
      return true;
   }

   const auto& alt_name = cert.subject_alt_name();

   if(exceeds_limit(cert.subject_dn().count(), alt_name.count(), permitted().size())) {
      return false;
   }

   if(reject_unknown) {
      if(m_permitted_name_types.contains(GeneralName::NameType::Other) && !alt_name.other_names().empty()) {
         return false;
      }
      if(m_permitted_name_types.contains(GeneralName::NameType::URI) && !alt_name.uris().empty()) {
         return false;
      }
      if(m_permitted_name_types.contains(GeneralName::NameType::RFC822) && !alt_name.email().empty()) {
         return false;
      }
   }

   auto is_permitted_dn = [&](const X509_DN& dn) {
      // If no restrictions, then immediate accept
      if(!m_permitted_name_types.contains(GeneralName::NameType::DN)) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_dn(dn)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   auto is_permitted_dns_name = [&](const std::string& name) {
      if(name.empty() || name.starts_with(".")) {
         return false;
      }

      // If no restrictions, then immediate accept
      if(!m_permitted_name_types.contains(GeneralName::NameType::DNS)) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_dns(name)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   auto is_permitted_ipv4 = [&](uint32_t ipv4) {
      // If no restrictions, then immediate accept
      if(!m_permitted_name_types.contains(GeneralName::NameType::IPv4)) {
         return true;
      }

      for(const auto& c : m_permitted_subtrees) {
         if(c.base().matches_ipv4(ipv4)) {
            return true;
         }
      }

      // There is at least one permitted name and we didn't match
      return false;
   };

   if(!is_permitted_dn(cert.subject_dn())) {
      return false;
   }

   for(const auto& alt_dn : alt_name.directory_names()) {
      if(!is_permitted_dn(alt_dn)) {
         return false;
      }
   }

   for(const auto& alt_dns : alt_name.dns()) {
      if(!is_permitted_dns_name(alt_dns)) {
         return false;
      }
   }

   for(const auto& alt_ipv4 : alt_name.ipv4_address()) {
      if(!is_permitted_ipv4(alt_ipv4)) {
         return false;
      }
   }

   if(alt_name.count() == 0) {
      for(const auto& cn : cert.subject_info("Name")) {
         if(cn.find(".") != std::string::npos) {
            if(auto ipv4 = string_to_ipv4(cn)) {
               if(!is_permitted_ipv4(ipv4.value())) {
                  return false;
               }
            } else {
               if(!is_permitted_dns_name(cn)) {
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

   if(exceeds_limit(cert.subject_dn().count(), alt_name.count(), excluded().size())) {
      return true;
   }

   if(reject_unknown) {
      // This is one is overly broad: we should just reject if there is a name constraint
      // with the same OID as one of the other names
      if(m_excluded_name_types.contains(GeneralName::NameType::Other) && !alt_name.other_names().empty()) {
         return true;
      }
      if(m_excluded_name_types.contains(GeneralName::NameType::URI) && !alt_name.uris().empty()) {
         return true;
      }
      if(m_excluded_name_types.contains(GeneralName::NameType::RFC822) && !alt_name.email().empty()) {
         return true;
      }
   }

   auto is_excluded_dn = [&](const X509_DN& dn) {
      // If no restrictions, then immediate accept
      if(!m_excluded_name_types.contains(GeneralName::NameType::DN)) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().matches_dn(dn)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   auto is_excluded_dns_name = [&](const std::string& name) {
      if(name.empty() || name.starts_with(".")) {
         return true;
      }

      // If no restrictions, then immediate accept
      if(!m_excluded_name_types.contains(GeneralName::NameType::DNS)) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().matches_dns(name)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   auto is_excluded_ipv4 = [&](uint32_t ipv4) {
      // If no restrictions, then immediate accept
      if(!m_excluded_name_types.contains(GeneralName::NameType::IPv4)) {
         return false;
      }

      for(const auto& c : m_excluded_subtrees) {
         if(c.base().matches_ipv4(ipv4)) {
            return true;
         }
      }

      // There is at least one excluded name and we didn't match
      return false;
   };

   if(is_excluded_dn(cert.subject_dn())) {
      return true;
   }

   for(const auto& alt_dn : alt_name.directory_names()) {
      if(is_excluded_dn(alt_dn)) {
         return true;
      }
   }

   for(const auto& alt_dns : alt_name.dns()) {
      if(is_excluded_dns_name(alt_dns)) {
         return true;
      }
   }

   for(const auto& alt_ipv4 : alt_name.ipv4_address()) {
      if(is_excluded_ipv4(alt_ipv4)) {
         return true;
      }
   }

   if(alt_name.count() == 0) {
      for(const auto& cn : cert.subject_info("Name")) {
         if(cn.find(".") != std::string::npos) {
            if(auto ipv4 = string_to_ipv4(cn)) {
               if(is_excluded_ipv4(ipv4.value())) {
                  return true;
               }
            } else {
               if(is_excluded_dns_name(cn)) {
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
