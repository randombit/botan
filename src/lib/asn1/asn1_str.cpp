/*
* Simple ASN.1 String Types
* (C) 1999-2007,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <array>

namespace Botan {

namespace {

class ASN1_String_Codepoint_Validator final {
   public:
      constexpr ASN1_String_Codepoint_Validator() : m_table(make_table()) {}

      constexpr bool valid_encoding(std::string_view str, ASN1_Type tag) const {
         const uint8_t mask = mask_for(tag);
         for(const char c : str) {
            const uint8_t codepoint = static_cast<uint8_t>(c);
            const bool is_valid = (m_table[codepoint] & mask) != 0;

            if(!is_valid) {
               return false;
            }
         }

         return true;
      }

   private:
      static constexpr uint8_t Numeric_String = 0x01;
      static constexpr uint8_t Printable_String = 0x02;
      static constexpr uint8_t IA5_String = 0x04;
      static constexpr uint8_t Visible_String = 0x08;

      static constexpr uint8_t mask_for(ASN1_Type tag) {
         switch(tag) {
            case ASN1_Type::NumericString:
               return Numeric_String;
            case ASN1_Type::PrintableString:
               return Printable_String;
            case ASN1_Type::Ia5String:
               return IA5_String;
            case ASN1_Type::VisibleString:
               return Visible_String;
            default:
               return 0;
         }
      }

      static constexpr std::array<uint8_t, 256> make_table() {
         std::array<uint8_t, 256> table = {};

         for(size_t i = 0; i != table.size(); ++i) {
            const auto c = static_cast<uint8_t>(i);

            // Don't allow embedded null in IA5 even if technically valid
            if(c >= 1 && c <= 0x7F) {
               table[i] |= IA5_String;
            }

            if(c >= 0x20 && c <= 0x7E) {
               table[i] |= Visible_String;
            }

            if(c == ' ' || (c >= '0' && c <= '9')) {
               table[i] |= Numeric_String;
            }

            if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '\'' ||
               c == '(' || c == ')' || c == '+' || c == ',' || c == '-' || c == '.' || c == '/' || c == ':' ||
               c == '=' || c == '?') {
               table[i] |= Printable_String;
            }
         }

         return table;
      }

      std::array<uint8_t, 256> m_table;
};

constexpr ASN1_String_Codepoint_Validator g_char_validator;

bool is_utf8_subset_string_type(ASN1_Type tag) {
   return (tag == ASN1_Type::NumericString || tag == ASN1_Type::PrintableString || tag == ASN1_Type::VisibleString ||
           tag == ASN1_Type::Ia5String || tag == ASN1_Type::Utf8String);
}

bool is_asn1_string_type(ASN1_Type tag) {
   return (is_utf8_subset_string_type(tag) || tag == ASN1_Type::TeletexString || tag == ASN1_Type::BmpString ||
           tag == ASN1_Type::UniversalString);
}

bool is_valid_asn1_string_content(const std::string& str, ASN1_Type tag) {
   BOTAN_ASSERT_NOMSG(is_utf8_subset_string_type(tag));

   switch(tag) {
      case ASN1_Type::Utf8String:
         return is_valid_utf8(str);
      case ASN1_Type::NumericString:
      case ASN1_Type::PrintableString:
      case ASN1_Type::Ia5String:
      case ASN1_Type::VisibleString:
         return g_char_validator.valid_encoding(str, tag);
      default:
         return false;
   }
}

ASN1_Type choose_encoding(std::string_view str) {
   if(g_char_validator.valid_encoding(str, ASN1_Type::PrintableString)) {
      return ASN1_Type::PrintableString;
   } else {
      return ASN1_Type::Utf8String;
   }
}

}  // namespace

//static
bool ASN1_String::is_string_type(ASN1_Type tag) {
   return is_asn1_string_type(tag);
}

ASN1_String::ASN1_String(std::string_view str, ASN1_Type t) : m_utf8_str(str), m_tag(t) {
   if(!is_utf8_subset_string_type(m_tag)) {
      throw Invalid_Argument("ASN1_String only supports encoding to UTF-8 or a UTF-8 subset");
   }

   if(!is_valid_asn1_string_content(m_utf8_str, m_tag)) {
      throw Invalid_Argument(fmt("ASN1_String: Invalid {} encoding", asn1_tag_to_string(m_tag)));
   }
}

ASN1_String::ASN1_String(std::string_view str) : ASN1_String(str, choose_encoding(str)) {}

/*
* DER encode an ASN1_String
*/
void ASN1_String::encode_into(DER_Encoder& encoder) const {
   if(is_utf8_subset_string_type(tagging())) {
      encoder.add_object(tagging(), ASN1_Class::Universal, m_utf8_str);
   } else {
      // BMP/Universal/Teletex: m_utf8_str is the UTF-8 conversion, m_data is the wire form
      encoder.add_object(tagging(), ASN1_Class::Universal, m_data.data(), m_data.size());
   }
}

/*
* Decode a BER encoded ASN1_String
*/
void ASN1_String::decode_from(BER_Decoder& source) {
   const BER_Object obj = source.get_next_object();

   if(obj.get_class() != ASN1_Class::Universal || !is_asn1_string_type(obj.type())) {
      auto typ = static_cast<uint32_t>(obj.type());
      auto cls = static_cast<uint32_t>(obj.get_class());
      throw Decoding_Error(fmt("ASN1_String: Unknown string type {}/{}", typ, cls));
   }

   m_tag = obj.type();
   m_data.assign(obj.bits(), obj.bits() + obj.length());

   if(m_tag == ASN1_Type::BmpString) {
      m_utf8_str = ucs2_to_utf8(m_data);
   } else if(m_tag == ASN1_Type::UniversalString) {
      m_utf8_str = ucs4_to_utf8(m_data);
   } else if(m_tag == ASN1_Type::TeletexString) {
      /*
      TeletexString is nominally ITU T.61 not ISO-8859-1 but it seems
      the majority of implementations actually used that charset here.
      */
      m_utf8_str = latin1_to_utf8(m_data);
   } else {
      // All other supported string types are UTF-8 or some subset thereof
      m_utf8_str = ASN1::to_string(obj);

      if(!is_valid_asn1_string_content(m_utf8_str, m_tag)) {
         throw Decoding_Error(fmt("ASN1_String: Invalid {} encoding", asn1_tag_to_string(m_tag)));
      }
   }
}

}  // namespace Botan
