/*
* AlternativeName
* (C) 1999-2007 Jack Lloyd
*     2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_alt_name.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/internal/stl_util.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

/*
* Check if type is a known ASN.1 string type
*/
bool is_string_type(ASN1_Tag tag)
   {
   return (tag == NUMERIC_STRING ||
           tag == PRINTABLE_STRING ||
           tag == VISIBLE_STRING ||
           tag == T61_STRING ||
           tag == IA5_STRING ||
           tag == UTF8_STRING ||
           tag == BMP_STRING);
   }

}

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
                                    const std::string& str)
   {
   if(type.empty() || str.empty())
      return;

   auto range = m_alt_info.equal_range(type);
   for(auto j = range.first; j != range.second; ++j)
      if(j->second == str)
         return;

   multimap_insert(m_alt_info, type, str);
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
* Get the attributes of this alternative name
*/
std::multimap<std::string, std::string> AlternativeName::get_attributes() const
   {
   return m_alt_info;
   }

/*
* Get the otherNames
*/
std::multimap<OID, ASN1_String> AlternativeName::get_othernames() const
   {
   return m_othernames;
   }

/*
* Return all of the alternative names
*/
std::multimap<std::string, std::string> AlternativeName::contents() const
   {
   std::multimap<std::string, std::string> names;

   for(auto i = m_alt_info.begin(); i != m_alt_info.end(); ++i)
      multimap_insert(names, i->first, i->second);

   for(auto i = m_othernames.begin(); i != m_othernames.end(); ++i)
      multimap_insert(names, OIDS::lookup(i->first), i->second.value());

   return names;
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
         encoder.add_object(tagging, CONTEXT_SPECIFIC, asn1_string.iso_8859());
         }
      else if(type == "IP")
         {
         const uint32_t ip = string_to_ipv4(i->second);
         uint8_t ip_buf[4] = { 0 };
         store_be(ip, ip_buf);
         encoder.add_object(tagging, CONTEXT_SPECIFIC, ip_buf, 4);
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

   while(names.more_items())
      {
      BER_Object obj = names.get_next_object();
      if((obj.class_tag != CONTEXT_SPECIFIC) &&
         (obj.class_tag != (CONTEXT_SPECIFIC | CONSTRUCTED)))
         continue;

      const ASN1_Tag tag = obj.type_tag;

      if(tag == 0)
         {
         BER_Decoder othername(obj.value);

         OID oid;
         othername.decode(oid);
         if(othername.more_items())
            {
            BER_Object othername_value_outer = othername.get_next_object();
            othername.verify_end();

            if(othername_value_outer.type_tag != ASN1_Tag(0) ||
               othername_value_outer.class_tag !=
                   (CONTEXT_SPECIFIC | CONSTRUCTED)
               )
               throw Decoding_Error("Invalid tags on otherName value");

            BER_Decoder othername_value_inner(othername_value_outer.value);

            BER_Object value = othername_value_inner.get_next_object();
            othername_value_inner.verify_end();

            const ASN1_Tag value_type = value.type_tag;

            if(is_string_type(value_type) && value.class_tag == UNIVERSAL)
               add_othername(oid, ASN1::to_string(value), value_type);
            }
         }
      else if(tag == 1 || tag == 2 || tag == 6)
         {
         const std::string value = Charset::transcode(ASN1::to_string(obj),
                                                      LATIN1_CHARSET,
                                                      LOCAL_CHARSET);

         if(tag == 1) add_attribute("RFC822", value);
         if(tag == 2) add_attribute("DNS", value);
         if(tag == 6) add_attribute("URI", value);
         }
      else if(tag == 7)
         {
         if(obj.value.size() == 4)
            {
            const uint32_t ip = load_be<uint32_t>(&obj.value[0], 0);
            add_attribute("IP", ipv4_to_string(ip));
            }
         }

      }
   }

}
