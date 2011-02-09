/*
* Simple ASN.1 String Types
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eac_asn_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <sstream>
#include <ios>

namespace Botan {

/*
* Create an ASN1_EAC_String
*/
ASN1_EAC_String::ASN1_EAC_String(const std::string& str, ASN1_Tag t) : tag(t)
   {
   iso_8859_str = Charset::transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
   if (!sanity_check())
      {
      throw Invalid_Argument("attempted to construct ASN1_EAC_String with illegal characters");
      }
   }

/*
* Return this string in ISO 8859-1 encoding
*/
std::string ASN1_EAC_String::iso_8859() const
   {
   return iso_8859_str;
   }

/*
* Return this string in local encoding
*/
std::string ASN1_EAC_String::value() const
   {
   return Charset::transcode(iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
   }

/*
* Return the type of this string object
*/
ASN1_Tag ASN1_EAC_String::tagging() const
   {
   return tag;
   }

/*
* DER encode an ASN1_EAC_String
*/
void ASN1_EAC_String::encode_into(DER_Encoder& encoder) const
   {
   std::string value = iso_8859();
   encoder.add_object(tagging(), APPLICATION, value);
   }

/*
* Decode a BER encoded ASN1_EAC_String
*/
void ASN1_EAC_String::decode_from(BER_Decoder& source)
   {
   BER_Object obj = source.get_next_object();
   if (obj.type_tag != this->tag)
      {

      std::string message("decoding type mismatch for ASN1_EAC_String, tag is ");
      std::stringstream ss;
      std::string str_is;
      ss << std::hex << obj.type_tag;
      ss >> str_is;
      message.append(str_is);
      message.append(", while it should be ");
      std::stringstream ss2;
      std::string str_should;
      ss2 << std::hex << this->tag;
      ss2 >> str_should;
      message.append(str_should);
      throw Decoding_Error(message);
      }
   Character_Set charset_is;
   charset_is = LATIN1_CHARSET;

   try
      {
      *this = ASN1_EAC_String(
         Charset::transcode(ASN1::to_string(obj), charset_is, LOCAL_CHARSET),
         obj.type_tag);
      }
   catch (Invalid_Argument inv_arg)
      {
      throw Decoding_Error(std::string("error while decoding ASN1_EAC_String: ") + std::string(inv_arg.what()));
      }
   }

// checks for compliance to the alphabet defined in TR-03110 v1.10, 2007-08-20
// p. 43
bool ASN1_EAC_String::sanity_check() const
   {
   const byte* rep = reinterpret_cast<const byte*>(iso_8859_str.data());
   const u32bit rep_len = iso_8859_str.size();
   for (u32bit i=0; i<rep_len; i++)
      {
      if ((rep[i] < 0x20) || ((rep[i] >= 0x7F) && (rep[i] < 0xA0)))
         {
         return false;
         }
      }
   return true;
   }

bool operator==(const ASN1_EAC_String& lhs, const ASN1_EAC_String& rhs)
   {
   return (lhs.iso_8859() == rhs.iso_8859());
   }

ASN1_Car::ASN1_Car(std::string const& str)
   : ASN1_EAC_String(str, ASN1_Tag(2))
   {}

ASN1_Chr::ASN1_Chr(std::string const& str)
   : ASN1_EAC_String(str, ASN1_Tag(32))
   {}

}
