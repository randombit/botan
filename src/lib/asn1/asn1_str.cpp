/*
* Simple ASN.1 String Types
* (C) 1999-2007,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/internal/charset.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

/*
* Choose an encoding for the string
*/
ASN1_Type choose_encoding(const std::string& str)
   {
   auto all_printable = CT::Mask<uint8_t>::set();

   for(size_t i = 0; i != str.size(); ++i)
      {
      const uint8_t c = static_cast<uint8_t>(str[i]);

      auto is_alpha_lower = CT::Mask<uint8_t>::is_within_range(c, 'a', 'z');
      auto is_alpha_upper = CT::Mask<uint8_t>::is_within_range(c, 'A', 'Z');
      auto is_decimal = CT::Mask<uint8_t>::is_within_range(c, '0', '9');

      auto is_print_punc = CT::Mask<uint8_t>::is_any_of(c, {
            ' ', '(', ')', '+', ',', '=', ',', '-', '.', '/',
            ':', '=', '?'});

      auto is_printable = is_alpha_lower | is_alpha_upper | is_decimal | is_print_punc;

      all_printable &= is_printable;
      }

   if(all_printable.is_set())
      return ASN1_Type::PrintableString;
   else
      return ASN1_Type::Utf8String;
   }

void assert_is_string_type(ASN1_Type tag)
   {
   if(!ASN1_String::is_string_type(tag))
      {
      throw Invalid_Argument("ASN1_String: Unknown string type " +
                             std::to_string(static_cast<uint32_t>(tag)));
      }
   }

}

//static
bool ASN1_String::is_string_type(ASN1_Type tag)
   {
   return (tag == ASN1_Type::NumericString ||
           tag == ASN1_Type::PrintableString ||
           tag == ASN1_Type::VisibleString ||
           tag == ASN1_Type::T61String ||
           tag == ASN1_Type::Ia5String ||
           tag == ASN1_Type::Utf8String ||
           tag == ASN1_Type::BmpString ||
           tag == ASN1_Type::UniversalString);
   }


/*
* Create an ASN1_String
*/
ASN1_String::ASN1_String(const std::string& str, ASN1_Type t) : m_utf8_str(str), m_tag(t)
   {
   assert_is_string_type(m_tag);
   }

/*
* Create an ASN1_String
*/
ASN1_String::ASN1_String(const std::string& str) :
   ASN1_String(str, choose_encoding(str))
   {}

/*
* DER encode an ASN1_String
*/
void ASN1_String::encode_into(DER_Encoder& encoder) const
   {
   if(m_data.empty())
      {
      encoder.add_object(tagging(), ASN1_Class::Universal, m_utf8_str);
      }
   else
      {
      // If this string was decoded, reserialize using original encoding
      encoder.add_object(tagging(), ASN1_Class::Universal, m_data.data(), m_data.size());
      }
   }

/*
* Decode a BER encoded ASN1_String
*/
void ASN1_String::decode_from(BER_Decoder& source)
   {
   BER_Object obj = source.get_next_object();

   assert_is_string_type(obj.type());

   m_tag = obj.type();
   m_data.assign(obj.bits(), obj.bits() + obj.length());

   if(m_tag == ASN1_Type::BmpString)
      {
      m_utf8_str = ucs2_to_utf8(m_data.data(), m_data.size());
      }
   else if(m_tag == ASN1_Type::UniversalString)
      {
      m_utf8_str = ucs4_to_utf8(m_data.data(), m_data.size());
      }
   else
      {
      // All other supported string types are UTF-8 or some subset thereof
      m_utf8_str = ASN1::to_string(obj);
      }
   }

}
