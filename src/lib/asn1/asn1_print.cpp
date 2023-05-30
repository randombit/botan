/*
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_print.h>

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/hex.h>
#include <botan/internal/fmt.h>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace Botan {

namespace {

bool all_printable_chars(const uint8_t bits[], size_t bits_len) {
   for(size_t i = 0; i != bits_len; ++i) {
      int c = bits[i];
      if(c > 127) {
         return false;
      }

      if((std::isalnum(c) || c == '.' || c == ':' || c == '/' || c == '-') == false) {
         return false;
      }
   }
   return true;
}

/*
* Special hack to handle GeneralName [2] and [6] (DNS name and URI)
*/
bool possibly_a_general_name(const uint8_t bits[], size_t bits_len) {
   if(bits_len <= 2) {
      return false;
   }

   if(bits[0] != 0x82 && bits[0] != 0x86) {
      return false;
   }

   if(bits[1] != bits_len - 2) {
      return false;
   }

   if(all_printable_chars(bits + 2, bits_len - 2) == false) {
      return false;
   }

   return true;
}

}  // namespace

std::string ASN1_Formatter::print(const uint8_t in[], size_t len) const {
   std::ostringstream output;
   print_to_stream(output, in, len);
   return output.str();
}

void ASN1_Formatter::print_to_stream(std::ostream& output, const uint8_t in[], size_t len) const {
   BER_Decoder dec(in, len);
   decode(output, dec, 0);
}

void ASN1_Formatter::decode(std::ostream& output, BER_Decoder& decoder, size_t level) const {
   BER_Object obj = decoder.get_next_object();

   const bool recurse_deeper = (m_max_depth == 0 || level < m_max_depth);

   while(obj.is_set()) {
      const ASN1_Type type_tag = obj.type();
      const ASN1_Class class_tag = obj.get_class();
      const size_t length = obj.length();

      /* hack to insert the tag+length back in front of the stuff now
         that we've gotten the type info */
      std::vector<uint8_t> bits;
      DER_Encoder(bits).add_object(type_tag, class_tag, obj.bits(), obj.length());

      BER_Decoder data(bits);

      if(intersects(class_tag, ASN1_Class::Constructed)) {
         BER_Decoder cons_info(obj.bits(), obj.length());

         if(recurse_deeper) {
            output << format(type_tag, class_tag, level, length, "");
            decode(output, cons_info, level + 1);  // recurse
         } else {
            output << format(type_tag, class_tag, level, length, format_bin(type_tag, class_tag, bits));
         }
      } else if(intersects(class_tag, ASN1_Class::Application) || intersects(class_tag, ASN1_Class::ContextSpecific)) {
         bool success_parsing_cs = false;

         if(m_print_context_specific) {
            try {
               if(possibly_a_general_name(bits.data(), bits.size())) {
                  output << format(
                     type_tag, class_tag, level, level, std::string(cast_uint8_ptr_to_char(&bits[2]), bits.size() - 2));
                  success_parsing_cs = true;
               } else if(recurse_deeper) {
                  std::vector<uint8_t> inner_bits;
                  data.decode(inner_bits, type_tag);

                  BER_Decoder inner(inner_bits);
                  std::ostringstream inner_data;
                  decode(inner_data, inner, level + 1);  // recurse
                  output << inner_data.str();
                  success_parsing_cs = true;
               }
            } catch(...) {}
         }

         if(success_parsing_cs == false) {
            output << format(type_tag, class_tag, level, length, format_bin(type_tag, class_tag, bits));
         }
      } else if(type_tag == ASN1_Type::ObjectId) {
         OID oid;
         data.decode(oid);

         const std::string name = oid.human_name_or_empty();
         const std::string oid_str = oid.to_string();

         if(name.empty()) {
            output << format(type_tag, class_tag, level, length, oid_str);
         } else {
            output << format(type_tag, class_tag, level, length, fmt("{} [{}]", name, oid_str));
         }
      } else if(type_tag == ASN1_Type::Integer || type_tag == ASN1_Type::Enumerated) {
         BigInt number;

         if(type_tag == ASN1_Type::Integer) {
            data.decode(number);
         } else if(type_tag == ASN1_Type::Enumerated) {
            data.decode(number, ASN1_Type::Enumerated, class_tag);
         }

         output << format(type_tag, class_tag, level, length, format_bn(number));
      } else if(type_tag == ASN1_Type::Boolean) {
         bool boolean;
         data.decode(boolean);
         output << format(type_tag, class_tag, level, length, (boolean ? "true" : "false"));
      } else if(type_tag == ASN1_Type::Null) {
         output << format(type_tag, class_tag, level, length, "");
      } else if(type_tag == ASN1_Type::OctetString || type_tag == ASN1_Type::BitString) {
         std::vector<uint8_t> decoded_bits;
         data.decode(decoded_bits, type_tag);
         bool printing_octet_string_worked = false;

         if(recurse_deeper) {
            try {
               BER_Decoder inner(decoded_bits);

               std::ostringstream inner_data;
               decode(inner_data, inner, level + 1);  // recurse

               output << format(type_tag, class_tag, level, length, "");
               output << inner_data.str();
               printing_octet_string_worked = true;
            } catch(...) {}
         }

         if(!printing_octet_string_worked) {
            output << format(type_tag, class_tag, level, length, format_bin(type_tag, class_tag, decoded_bits));
         }
      } else if(ASN1_String::is_string_type(type_tag)) {
         ASN1_String str;
         data.decode(str);
         output << format(type_tag, class_tag, level, length, str.value());
      } else if(type_tag == ASN1_Type::UtcTime || type_tag == ASN1_Type::GeneralizedTime) {
         ASN1_Time time;
         data.decode(time);
         output << format(type_tag, class_tag, level, length, time.readable_string());
      } else {
         output << "Unknown ASN.1 tag class=" << static_cast<int>(class_tag) << " type=" << static_cast<int>(type_tag)
                << "\n";
      }

      obj = decoder.get_next_object();
   }
}

namespace {

std::string format_type(ASN1_Type type_tag, ASN1_Class class_tag) {
   if(class_tag == ASN1_Class::Universal) {
      return asn1_tag_to_string(type_tag);
   }

   if(class_tag == ASN1_Class::Constructed && (type_tag == ASN1_Type::Sequence || type_tag == ASN1_Type::Set)) {
      return asn1_tag_to_string(type_tag);
   }

   std::ostringstream oss;

   if(intersects(class_tag, ASN1_Class::Constructed)) {
      oss << "cons ";
   }

   oss << "[" << std::to_string(static_cast<uint32_t>(type_tag)) << "]";

   if(intersects(class_tag, ASN1_Class::Application)) {
      oss << " appl";
   }
   if(intersects(class_tag, ASN1_Class::ContextSpecific)) {
      oss << " context";
   }

   return oss.str();
}

}  // namespace

std::string ASN1_Pretty_Printer::format(
   ASN1_Type type_tag, ASN1_Class class_tag, size_t level, size_t length, std::string_view value) const {
   bool should_skip = false;

   if(value.length() > m_print_limit) {
      should_skip = true;
   }

   if((type_tag == ASN1_Type::OctetString || type_tag == ASN1_Type::BitString) &&
      value.length() > m_print_binary_limit) {
      should_skip = true;
   }

   level += m_initial_level;

   std::ostringstream oss;

   oss << "  d=" << std::setw(2) << level << ", l=" << std::setw(4) << length << ":" << std::string(level + 1, ' ')
       << format_type(type_tag, class_tag);

   if(!value.empty() && !should_skip) {
      const size_t current_pos = static_cast<size_t>(oss.tellp());
      const size_t spaces_to_align = (current_pos >= m_value_column) ? 1 : (m_value_column - current_pos);

      oss << std::string(spaces_to_align, ' ') << value;
   }

   oss << "\n";

   return oss.str();
}

std::string ASN1_Pretty_Printer::format_bin(ASN1_Type /*type_tag*/,
                                            ASN1_Class /*class_tag*/,
                                            const std::vector<uint8_t>& vec) const {
   if(all_printable_chars(vec.data(), vec.size())) {
      return std::string(cast_uint8_ptr_to_char(vec.data()), vec.size());
   } else {
      return hex_encode(vec);
   }
}

std::string ASN1_Pretty_Printer::format_bn(const BigInt& bn) const {
   if(bn.bits() < 16) {
      return bn.to_dec_string();
   } else {
      return bn.to_hex_string();
   }
}

}  // namespace Botan
