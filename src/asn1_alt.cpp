/*************************************************
* AlternativeName Source File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
#include <botan/stl_util.h>
#include <botan/charset.h>

namespace Botan {

/*************************************************
* Create an AlternativeName                      *
*************************************************/
AlternativeName::AlternativeName(const std::string& email_addr,
                                 const std::string& uri,
                                 const std::string& dns)
   {
   add_attribute("RFC822", email_addr);
   add_attribute("DNS", dns);
   add_attribute("URI", uri);
   }

/*************************************************
* Add an attribute to an alternative name        *
*************************************************/
void AlternativeName::add_attribute(const std::string& type,
                                    const std::string& str)
   {
   if(type == "" || str == "")
      return;

   typedef std::multimap<std::string, std::string>::iterator iter;
   std::pair<iter, iter> range = alt_info.equal_range(type);
   for(iter j = range.first; j != range.second; ++j)
      if(j->second == str)
         return;

   multimap_insert(alt_info, type, str);
   }

/*************************************************
* Add an OtherName field                         *
*************************************************/
void AlternativeName::add_othername(const OID& oid, const std::string& value,
                                    ASN1_Tag type)
   {
   if(value == "")
      return;
   multimap_insert(othernames, oid, ASN1_String(value, type));
   }

/*************************************************
* Get the attributes of this alternative name    *
*************************************************/
std::multimap<std::string, std::string> AlternativeName::get_attributes() const
   {
   return alt_info;
   }

/*************************************************
* Get the otherNames                             *
*************************************************/
std::multimap<OID, ASN1_String> AlternativeName::get_othernames() const
   {
   return othernames;
   }

/*************************************************
* Return if this object has anything useful      *
*************************************************/
bool AlternativeName::has_items() const
   {
   return (alt_info.size() > 0 || othernames.size() > 0);
   }

namespace {

/*************************************************
* DER encode an AlternativeName entry            *
*************************************************/
void encode_entries(DER_Encoder& encoder,
                    const std::multimap<std::string, std::string>& attr,
                    const std::string& type, ASN1_Tag tagging)
   {
   typedef std::multimap<std::string, std::string>::const_iterator iter;

   std::pair<iter, iter> range = attr.equal_range(type);
   for(iter j = range.first; j != range.second; ++j)
      {
      ASN1_String asn1_string(j->second, IA5_STRING);
      DER::encode(encoder, asn1_string, tagging, CONTEXT_SPECIFIC);
      }
   }

}

/*************************************************
* DER encode an AlternativeName extension        *
*************************************************/
void AlternativeName::encode_into(DER_Encoder& der) const
   {
   der.start_sequence();

   encode_entries(der, alt_info, "RFC822", ASN1_Tag(1));
   encode_entries(der, alt_info, "DNS", ASN1_Tag(2));
   encode_entries(der, alt_info, "URI", ASN1_Tag(6));

   std::multimap<OID, ASN1_String>::const_iterator i;
   for(i = othernames.begin(); i != othernames.end(); ++i)
      {
      der.start_explicit(ASN1_Tag(0))
         .encode(i->first)
         .start_explicit(ASN1_Tag(0))
            .encode(i->second)
         .end_explicit(ASN1_Tag(0))
      .end_explicit(ASN1_Tag(0));
      }

   der.end_sequence();
   }

namespace BER {

/*************************************************
* Decode a BER encoded AlternativeName           *
*************************************************/
void decode(BER_Decoder& source, AlternativeName& alt_name)
   {
   BER_Decoder names = BER::get_subsequence(source);
   while(names.more_items())
      {
      BER_Object obj = names.get_next_object();
      if((obj.class_tag != CONTEXT_SPECIFIC) &&
         (obj.class_tag != (CONTEXT_SPECIFIC | CONSTRUCTED)))
         continue;

      ASN1_Tag tag = obj.type_tag;

      if(tag == 0)
         {
         BER_Decoder othername(obj.value);

         OID oid;
         BER::decode(othername, oid);
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

            ASN1_Tag value_type = value.type_tag;

            if(is_string_type(value_type) && value.class_tag == UNIVERSAL)
               alt_name.add_othername(oid, BER::to_string(value), value_type);
            }
         }
      else if(tag == 1 || tag == 2 || tag == 6)
         {
         const std::string value = iso2local(BER::to_string(obj));

         if(tag == 1) alt_name.add_attribute("RFC822", value);
         if(tag == 2) alt_name.add_attribute("DNS", value);
         if(tag == 6) alt_name.add_attribute("URI", value);
         }

      }
   }

}

}
