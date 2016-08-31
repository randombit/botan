/*
* X.509 Name Constraint
* (C) 2015 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/name_constraint.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/charset.h>
#include <botan/loadstor.h>
#include <botan/x509_dn.h>
#include <botan/x509cert.h>
#include <sstream>

namespace Botan {

GeneralName::GeneralName(const std::string& v) : GeneralName()
   {
   size_t p = v.find(':');

   if(p != std::string::npos)
      {
      m_type = v.substr(0,p);
      m_name = v.substr(p + 1,std::string::npos);
      }
   else
      {
      throw Invalid_Argument("Failed to decode Name Constraint");
      }
   }

void GeneralName::encode_into(class DER_Encoder&) const
   {
   throw Not_Implemented("GeneralName encoding");
   }

void GeneralName::decode_from(class BER_Decoder& ber)
   {
   BER_Object obj = ber.get_next_object();
   if((obj.class_tag != CONTEXT_SPECIFIC) &&
      (obj.class_tag != (CONTEXT_SPECIFIC | CONSTRUCTED)))
      throw Decoding_Error("Invalid class tag while decoding GeneralName");

   const ASN1_Tag tag = obj.type_tag;

   if(tag == 1 || tag == 2 || tag == 6)
      {
      m_name = Charset::transcode(ASN1::to_string(obj),LATIN1_CHARSET,LOCAL_CHARSET);

      if(tag == 1)
         {
         m_type = "RFC822";
         }
      else if(tag == 2)
         {
         m_type = "DNS";
         }
      else if(tag == 6)
         {
         m_type = "URI";
         }
      }
   else if(tag == 4)
      {
      X509_DN dn;
      std::multimap<std::string, std::string> nam;
      BER_Decoder dec(obj.value);
      std::stringstream ss;

      dn.decode_from(dec);
      ss << dn;

      m_name = ss.str();
      m_type = "DN";
      }
   else if(tag == 7)
      {
      if(obj.value.size() == 8)
         {
         const std::vector<byte> ip(obj.value.begin(),obj.value.begin() + 4);
         const std::vector<byte> net(obj.value.begin() + 4,obj.value.end());
         m_type = "IP";
         m_name = ipv4_to_string(load_be<u32bit>(ip.data(),0)) + "/" + ipv4_to_string(load_be<u32bit>(net.data(),0));
         }
      else if(obj.value.size() == 32)
         {
         throw Decoding_Error("Unsupported IPv6 name constraint");
         }
      else
         {
         throw Decoding_Error("Invalid IP name constraint size " +
                              std::to_string(obj.value.size()));
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
   std::function<bool(const GeneralName*,const std::string&)> match_fn;

   if(type() == "DNS")
      {
      match_fn = std::mem_fn(&GeneralName::matches_dns);
      nam = cert.subject_info("DNS");

      if(nam.empty())
         {
         nam = cert.subject_info("CN");
         }
      }
   else if(type() == "DN")
      {
      match_fn = std::mem_fn(&GeneralName::matches_dn);

      std::stringstream ss;
      ss << cert.subject_dn();
      nam.push_back(ss.str());
      }
   else if(type() == "IP")
      {
      match_fn = std::mem_fn(&GeneralName::matches_ip);
      nam = cert.subject_info("IP");
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
      bool m = match_fn(this,n);

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
      return constr == nam.substr(nam.size() - constr.size(),constr.size());
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
   int trys = 0;

   for(const std::pair<OID,std::string>& c: my_dn.get_attributes())
      {
      auto i = attr.equal_range(c.first);

      if(i.first != i.second)
         {
         trys += 1;
         ret &= i.first->second == c.second;
         }
      }

   return trys > 0 && ret;
   }

bool GeneralName::matches_ip(const std::string& nam) const
   {
   u32bit ip = string_to_ipv4(nam);
   std::vector<std::string> p = split_on(name(),'/');

   if(p.size() != 2)
      throw Decoding_Error("failed to parse IPv4 address");

   u32bit net = string_to_ipv4(p.at(0));
   u32bit mask = string_to_ipv4(p.at(1));

   return (ip & mask) == net;
   }

std::ostream& operator<<(std::ostream& os, const GeneralName& gn)
   {
   os << gn.type() << ":" << gn.name();
   return os;
   }

GeneralSubtree::GeneralSubtree(const std::string& v) : GeneralSubtree()
   {
   size_t p0, p1;
   size_t min = std::stoull(v, &p0, 10);
   size_t max = std::stoull(v.substr(p0 + 1), &p1, 10);
   GeneralName gn(v.substr(p0 + p1 + 2));

   if(p0 > 0 && p1 > 0)
      {
      m_minimum = min;
      m_maximum = max;
      m_base = gn;
      }
   else
      {
      throw Invalid_Argument("Failed to decode Name Constraint");
      }
   }

void GeneralSubtree::encode_into(class DER_Encoder&) const
   {
   throw Not_Implemented("General Subtree encoding");
   }

void GeneralSubtree::decode_from(class BER_Decoder& ber)
   {
   ber.start_cons(SEQUENCE)
      .decode(m_base)
      .decode_optional(m_minimum,ASN1_Tag(0),CONTEXT_SPECIFIC,size_t(0))
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
