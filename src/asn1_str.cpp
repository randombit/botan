/*************************************************
* Simple ASN.1 String Types Source File          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
#include <botan/asn1_int.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <botan/conf.h>

namespace Botan {

namespace {

/*************************************************
* Choose an encoding for the string              *
*************************************************/
ASN1_Tag choose_encoding(const std::string& str)
   {
   static const byte IS_PRINTABLE[256] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
      0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

   for(u32bit j = 0; j != str.size(); ++j)
      if(!IS_PRINTABLE[(byte)str[j]])
         {
         const std::string type = Config::get_string("x509/ca/str_type");
         if(type == "utf8")   return UTF8_STRING;
         if(type == "latin1") return T61_STRING;
         throw Invalid_Argument("Bad setting for x509/ca/str_type: " + type);
         }
   return PRINTABLE_STRING;
   }

}

/*************************************************
* Check if type is a known ASN.1 string type     *
*************************************************/
bool is_string_type(ASN1_Tag tag)
   {
   if(tag == NUMERIC_STRING || tag == PRINTABLE_STRING ||
      tag == VISIBLE_STRING || tag == T61_STRING || tag == IA5_STRING ||
      tag == UTF8_STRING || tag == BMP_STRING)
      return true;
   return false;
   }

/*************************************************
* Create an ASN1_String                          *
*************************************************/
ASN1_String::ASN1_String(const std::string& str, ASN1_Tag t) : tag(t)
   {
   iso_8859_str = local2iso(str);
   if(tag == DIRECTORY_STRING)
      tag = choose_encoding(iso_8859_str);

   if(tag != NUMERIC_STRING &&
      tag != PRINTABLE_STRING &&
      tag != VISIBLE_STRING &&
      tag != T61_STRING &&
      tag != IA5_STRING &&
      tag != UTF8_STRING &&
      tag != BMP_STRING)
      throw Invalid_Argument("ASN1_String: Unknown string type " +
                             to_string(tag));
   }

/*************************************************
* Create an ASN1_String                          *
*************************************************/
ASN1_String::ASN1_String(const std::string& str)
   {
   iso_8859_str = local2iso(str);
   tag = choose_encoding(iso_8859_str);
   }

/*************************************************
* Return this string in ISO 8859-1 encoding      *
*************************************************/
std::string ASN1_String::iso_8859() const
   {
   return iso_8859_str;
   }

/*************************************************
* Return this string in local encoding           *
*************************************************/
std::string ASN1_String::value() const
   {
   return iso2local(iso_8859_str);
   }

/*************************************************
* Return the type of this string object          *
*************************************************/
ASN1_Tag ASN1_String::tagging() const
   {
   return tag;
   }

/*************************************************
* DER encode an ASN1_String                      *
*************************************************/
void ASN1_String::encode_into(DER_Encoder& encoder) const
   {
   std::string value = iso_8859();
   if(tagging() == UTF8_STRING)
      value = iso2utf(value);
   encoder.add_object(tagging(), UNIVERSAL, value);
   }

namespace DER {

/*************************************************
* DER encode an ASN1_String                      *
*************************************************/
void encode(DER_Encoder& encoder, const ASN1_String& string,
            ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(string.tagging() == UTF8_STRING)
      encoder.add_object(type_tag, class_tag, iso2utf(string.iso_8859()));
   else
      encoder.add_object(type_tag, class_tag, string.iso_8859());
   }

}

namespace BER {

namespace {

/*************************************************
* Do any UTF-8/Unicode decoding needed           *
*************************************************/
std::string convert_string(BER_Object obj, ASN1_Tag type)
   {
   if(type == BMP_STRING)
      {
      if(obj.value.size() % 2 == 1)
         throw BER_Decoding_Error("BMP STRING has an odd number of bytes");

      std::string value;
      for(u32bit j = 0; j != obj.value.size(); j += 2)
         {
         const byte c1 = obj.value[j];
         const byte c2 = obj.value[j+1];

         if(c1 != 0)
            throw BER_Decoding_Error("BMP STRING has non-Latin1 characters");

         value += (char)c2;
         }
      return iso2local(value);
      }
   else if(type == UTF8_STRING)
      return iso2local(utf2iso(BER::to_string(obj)));
   else
      return iso2local(BER::to_string(obj));
   }

}

/*************************************************
* Decode a BER encoded ASN1_String               *
*************************************************/
void decode(BER_Decoder& source, ASN1_String& string,
            ASN1_Tag expected_tag, ASN1_Tag real_tag)
   {
   BER_Object obj = source.get_next_object();
   if(obj.type_tag != expected_tag)
      throw BER_Bad_Tag("Unexpected string tag", obj.type_tag);

   string = ASN1_String(convert_string(obj, real_tag),  real_tag);
   }

/*************************************************
* Decode a BER encoded ASN1_String               *
*************************************************/
void decode(BER_Decoder& source, ASN1_String& string)
   {
   BER_Object obj = source.get_next_object();
   string = ASN1_String(convert_string(obj, obj.type_tag), obj.type_tag);
   }

}

}
