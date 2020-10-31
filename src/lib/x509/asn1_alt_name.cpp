/*
* AlternativeName
* (C) 1999-2007 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/internal/stl_util.h>
#include <botan/parsing.h>
#include <botan/loadstor.h>

#include <sstream>

namespace Botan {

/*
* Create an AlternativeName
*/
AlternativeName::AlternativeName(const std::string& email_addr,
                                 const std::string& uri,
                                 const std::string& dns,
                                 const std::string& ip)
   {
   add_attribute("RFC822", email_addr);
   add_attribute("DNS", dns);
   add_attribute("URI", uri);
   add_attribute("IP", ip);
   }

/*
* Add an attribute to an alternative name
*/
void AlternativeName::add_attribute(const std::string& type,
                                    const std::string& value)
   {
   if(type.empty() || value.empty())
      return;

   auto range = m_alt_info.equal_range(type);
   for(auto j = range.first; j != range.second; ++j)
      if(j->second == value)
         return;

   multimap_insert(m_alt_info, type, value);
   }

/*
* Add an OtherName field
*/
void AlternativeName::add_othername(const OID& oid, const std::string& value,
                                    ASN1_Tag type)
   {
   if(value.empty())
      return;
   multimap_insert(m_othernames, oid, ASN1_String(value, type));
   }

/*
* Return all of the alternative names
*/
std::multimap<std::string, std::string> AlternativeName::contents() const
   {
   std::multimap<std::string, std::string> names;

   for(auto i = m_alt_info.begin(); i != m_alt_info.end(); ++i)
      {
      multimap_insert(names, i->first, i->second);
      }

   for(auto i = m_othernames.begin(); i != m_othernames.end(); ++i)
      {
      multimap_insert(names, i->first.to_formatted_string(), i->second.value());
      }

   return names;
   }

bool AlternativeName::has_field(const std::string& attr) const
   {
   auto range = m_alt_info.equal_range(attr);
   return (range.first != range.second);
   }

std::string AlternativeName::get_first_attribute(const std::string& attr) const
   {
   auto i = m_alt_info.lower_bound(attr);
   if(i != m_alt_info.end() && i->first == attr)
      return i->second;

   return "";
   }

std::vector<std::string> AlternativeName::get_attribute(const std::string& attr) const
   {
   std::vector<std::string> results;
   auto range = m_alt_info.equal_range(attr);
   for(auto i = range.first; i != range.second; ++i)
      results.push_back(i->second);
   return results;
   }

X509_DN AlternativeName::dn() const
   {
   X509_DN dn;
   auto range = m_alt_info.equal_range("DN");

   for(auto i = range.first; i != range.second; ++i)
      {
      std::istringstream strm(i->second);
      strm >> dn;
      }

   return dn;
   }

/*
* Return if this object has anything useful
*/
bool AlternativeName::has_items() const
   {
   return (m_alt_info.size() > 0 || m_othernames.size() > 0);
   }

namespace {

/*
* DER encode an AlternativeName entry
*/
void encode_entries(DER_Encoder& encoder,
                    const std::multimap<std::string, std::string>& attr,
                    const std::string& type, ASN1_Tag tagging)
   {
   auto range = attr.equal_range(type);

   for(auto i = range.first; i != range.second; ++i)
      {
      if(type == "RFC822" || type == "DNS" || type == "URI")
         {
         ASN1_String asn1_string(i->second, IA5_STRING);
         encoder.add_object(tagging, CONTEXT_SPECIFIC, asn1_string.value());
         }
      else if(type == "IP")
         {
         const uint32_t ip = string_to_ipv4(i->second);
         uint8_t ip_buf[4] = { 0 };
         store_be(ip, ip_buf);
         encoder.add_object(tagging, CONTEXT_SPECIFIC, ip_buf, 4);
         }
      else if (type == "DN")
         {
         std::stringstream ss(i->second);
         X509_DN dn;
         ss >> dn;
         encoder.encode(dn);
         }
      }
   }

}

/*
* DER encode an AlternativeName extension
*/
void AlternativeName::encode_into(DER_Encoder& der) const
   {
   der.start_cons(SEQUENCE);

   encode_entries(der, m_alt_info, "RFC822", ASN1_Tag(1));
   encode_entries(der, m_alt_info, "DNS", ASN1_Tag(2));
   encode_entries(der, m_alt_info, "DN", ASN1_Tag(4));
   encode_entries(der, m_alt_info, "URI", ASN1_Tag(6));
   encode_entries(der, m_alt_info, "IP", ASN1_Tag(7));

   for(auto i = m_othernames.begin(); i != m_othernames.end(); ++i)
      {
      der.start_explicit(0)
         .encode(i->first)
         .start_explicit(0)
            .encode(i->second)
         .end_explicit()
      .end_explicit();
      }

   der.end_cons();
   }

/*
* Decode a BER encoded AlternativeName
*/
void AlternativeName::decode_from(BER_Decoder& source)
   {
   BER_Decoder names = source.start_cons(SEQUENCE);

   // FIXME this is largely a duplication of GeneralName::decode_from

   while(names.more_items())
      {
      BER_Object obj = names.get_next_object();

      if(obj.is_a(0, CONTEXT_SPECIFIC))
         {
         BER_Decoder othername(obj);

         OID oid;
         othername.decode(oid);
         if(othername.more_items())
            {
            BER_Object othername_value_outer = othername.get_next_object();
            othername.verify_end();

            if(othername_value_outer.is_a(0, ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED)) == false)
               throw Decoding_Error("Invalid tags on otherName value");

            BER_Decoder othername_value_inner(othername_value_outer);

            BER_Object value = othername_value_inner.get_next_object();
            othername_value_inner.verify_end();

            if(ASN1_String::is_string_type(value.type()) && value.get_class() == UNIVERSAL)
               {
               add_othername(oid, ASN1::to_string(value), value.type());
               }
            }
         }
      if(obj.is_a(1, CONTEXT_SPECIFIC))
         {
         add_attribute("RFC822", ASN1::to_string(obj));
         }
      else if(obj.is_a(2, CONTEXT_SPECIFIC))
         {
         add_attribute("DNS", ASN1::to_string(obj));
         }
      else if(obj.is_a(6, CONTEXT_SPECIFIC))
         {
         add_attribute("URI", ASN1::to_string(obj));
         }
      else if(obj.is_a(4, ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED)))
         {
         BER_Decoder dec(obj);
         X509_DN dn;
         std::stringstream ss;

         dec.decode(dn);
         ss << dn;

         add_attribute("DN", ss.str());
         }
      else if(obj.is_a(7, CONTEXT_SPECIFIC))
         {
         if(obj.length() == 4)
            {
            const uint32_t ip = load_be<uint32_t>(obj.bits(), 0);
            add_attribute("IP", ipv4_to_string(ip));
            }
         }

      }
   }

}
