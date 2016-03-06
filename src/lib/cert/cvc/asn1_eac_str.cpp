/*
* Simple ASN.1 String Types
* (C) 2007 FlexSecure GmbH
*     2008-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
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
ASN1_EAC_String::ASN1_EAC_String(const std::string& str, ASN1_Tag t) : m_tag(t)
   {
   m_iso_8859_str = Charset::transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);

   if(!sanity_check())
      throw Invalid_Argument("ASN1_EAC_String contains illegal characters");
   }

/*
* Return this string in ISO 8859-1 encoding
*/
std::string ASN1_EAC_String::iso_8859() const
   {
   return m_iso_8859_str;
   }

/*
* Return this string in local encoding
*/
std::string ASN1_EAC_String::value() const
   {
   return Charset::transcode(m_iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
   }

/*
* Return the type of this string object
*/
ASN1_Tag ASN1_EAC_String::tagging() const
   {
   return m_tag;
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

   if(obj.type_tag != m_tag)
      {
      std::stringstream ss;

      ss << "ASN1_EAC_String tag mismatch, tag was "
         << std::hex << obj.type_tag
         << " expected "
         << std::hex << m_tag;

      throw Decoding_Error(ss.str());
      }

   Character_Set charset_is;
   charset_is = LATIN1_CHARSET;

   try
      {
      *this = ASN1_EAC_String(
         Charset::transcode(ASN1::to_string(obj), LOCAL_CHARSET, charset_is),
         obj.type_tag);
      }
   catch(Invalid_Argument& inv_arg)
      {
      throw Decoding_Error(std::string("ASN1_EAC_String decoding failed: ") +
                           inv_arg.what());
      }
   }

// checks for compliance to the alphabet defined in TR-03110 v1.10, 2007-08-20
// p. 43
bool ASN1_EAC_String::sanity_check() const
   {
   const byte* rep = reinterpret_cast<const byte*>(m_iso_8859_str.data());
   const size_t rep_len = m_iso_8859_str.size();

   for(size_t i = 0; i != rep_len; ++i)
      {
      if((rep[i] < 0x20) || ((rep[i] >= 0x7F) && (rep[i] < 0xA0)))
         return false;
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
