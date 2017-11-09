/*
* Simple ASN.1 String Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_str.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/charset.h>

#include <codecvt>
#include <locale>

namespace Botan {

namespace {

/*
* Choose an encoding for the string
*/
ASN1_Tag choose_encoding(const std::string& str,
                         const std::string& type)
   {
   static const uint8_t IS_PRINTABLE[256] = {
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

   for(size_t i = 0; i != str.size(); ++i)
      {
      if(!IS_PRINTABLE[static_cast<uint8_t>(str[i])])
         {
         if(type == "utf8")   return UTF8_STRING;
         if(type == "latin1") return T61_STRING;
         throw Invalid_Argument("choose_encoding: Bad string type " + type);
         }
      }
   return PRINTABLE_STRING;
   }

}

template <typename CharT, class AllocT>
static std::string ucsX_to_utf8(const std::vector<byte, AllocT> &ucsX)
   {
   if (ucsX.size() % sizeof(CharT) != 0)
      {
      throw Invalid_Argument("cannot decode UCS string (wrong byte count)");
      }

   union
      {
      const byte  *as_char;
      const CharT *as_wide_char;
      };

   as_char = ucsX.data();
   const size_t wide_char_count = ucsX.size() / sizeof(CharT);

   using converter_t = std::codecvt_utf8<CharT, 0x10ffff, std::consume_header>;
   std::wstring_convert<converter_t, CharT> convert;
   return convert.to_bytes(as_wide_char, as_wide_char + wide_char_count);
   }

/*
* Create an ASN1_String
*/
ASN1_String::ASN1_String(const std::string& str, ASN1_Tag t) : m_utf8_str(str), m_tag(t)
   {

   if(m_tag == DIRECTORY_STRING)
      m_tag = choose_encoding(m_utf8_str, "utf8");

   if(m_tag != NUMERIC_STRING &&
      m_tag != PRINTABLE_STRING &&
      m_tag != VISIBLE_STRING &&
      m_tag != T61_STRING &&
      m_tag != IA5_STRING &&
      m_tag != UTF8_STRING &&
      m_tag != BMP_STRING &&
      m_tag != UNIVERSAL_STRING)
      throw Invalid_Argument("ASN1_String: Unknown string type " +
                             std::to_string(m_tag));
   }

/*
* Create an ASN1_String
*/
ASN1_String::ASN1_String(const std::string& str) : m_utf8_str(str), m_tag(choose_encoding(m_utf8_str, "utf8"))
   {}

/*
* Return this string in ISO 8859-1 encoding
*/
std::string ASN1_String::iso_8859() const
   {
   return Charset::transcode(m_utf8_str, LATIN1_CHARSET, UTF8_CHARSET);
   }

/*
* Return this string in UTF-8 encoding
*/
std::string ASN1_String::value() const
   {
   return m_utf8_str;
   }

/*
* Return the type of this string object
*/
ASN1_Tag ASN1_String::tagging() const
   {
   return m_tag;
   }

/*
* DER encode an ASN1_String
*/
void ASN1_String::encode_into(DER_Encoder& encoder) const
   {
   encoder.add_object(tagging(), UNIVERSAL, m_utf8_str);
   }

/*
* Decode a BER encoded ASN1_String
*/
void ASN1_String::decode_from(BER_Decoder& source)
   {
   BER_Object obj = source.get_next_object();

#if defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
   // using char32_t and char16_t (as suggested by the standard) leads to linker
   // errors on MSVC 2015 and 2017. This workaround was suggested here:
   //   https://social.msdn.microsoft.com/Forums/vstudio/en-US/
   //    8f40dcd8-c67f-4eba-9134-a19b9178e481/vs-2015-rc-linker-stdcodecvt-error
   using utf32_type = int32_t;
   using utf16_type = wchar_t;
#else
   using utf32_type = char32_t;
   using utf16_type = char16_t;
#endif

   if(obj.type_tag == UTF8_STRING)
      {
      *this = ASN1_String(ASN1::to_string(obj), obj.type_tag);
      }
   else if(obj.type_tag == BMP_STRING)
      {
      *this = ASN1_String(ucsX_to_utf8<utf16_type>(obj.value), obj.type_tag);
      }
   else if(obj.type_tag == UNIVERSAL_STRING)
      {
      *this = ASN1_String(ucsX_to_utf8<utf32_type>(obj.value), obj.type_tag);
      }
   else // IA5_STRING        - international ASCII characters
        // T61_STRING        - pretty much ASCII
        // PRINTABLE_STRING  - ASCII subset (a-z, A-Z, ' () +,-.?:/= and SPACE)
        // VISIBLE_STRING    - visible ASCII subset
        // NUMERIC_STRING    - ASCII subset (0-9 and SPACE)
      {
      *this = ASN1_String(
         Charset::transcode(ASN1::to_string(obj), UTF8_CHARSET, LATIN1_CHARSET),
         obj.type_tag);
      }
   }

}
