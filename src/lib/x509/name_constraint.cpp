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
   if(nam.size() == name().size())
      {
      return nam == name();
      }
   else if(name().size() > nam.size())
      {
      return false;
      }
   else // name.size() < nam.size()
      {
      std::string constr = name().front() == '.' ? name() : "." + name();
      // constr is suffix of nam
      return constr == nam.substr(nam.size() - constr.size(), constr.size());
      }
   }

bool GeneralName::matches_dn(const std::string& nam) const
   {
   std::stringstream ss(nam);
   std::stringstream tt(name());
   X509_DN nam_dn, my_dn;

   ss >> nam_dn;
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
}
