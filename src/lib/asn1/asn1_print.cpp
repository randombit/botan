/*
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_print.h>
#include <botan/bigint.h>
#include <botan/hex.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <iomanip>
#include <sstream>
#include <cctype>

namespace Botan {

namespace {

bool all_printable_chars(const uint8_t bits[], size_t bits_len)
   {
   for(size_t i = 0; i != bits_len; ++i)
      {
      int c = bits[i];
      if(c > 127)
         return false;

      if((std::isalnum(c) || c == '.' || c == ':' || c == '/' || c == '-') == false)
         return false;
      }
   return true;
   }

/*
* Special hack to handle GeneralName [2] and [6] (DNS name and URI)
*/
bool possibly_a_general_name(const uint8_t bits[], size_t bits_len)
   {
   if(bits_len <= 2)
      return false;

   if(bits[0] != 0x82 && bits[0] != 0x86)
      return false;

   if(bits[1] != bits_len - 2)
      return false;

   if(all_printable_chars(bits + 2, bits_len - 2) == false)
      return false;

   return true;
   }

}

std::string ASN1_Formatter::print(const uint8_t in[], size_t len) const
   {
   std::ostringstream output;
   print_to_stream(output, in, len);
   return output.str();
   }

void ASN1_Formatter::print_to_stream(std::ostream& output,
                                     const uint8_t in[],
                                     size_t len) const
   {
   BER_Decoder dec(in, len);
   decode(output, dec, 0);
   }

void ASN1_Formatter::decode(std::ostream& output,
                            BER_Decoder& decoder,
                            size_t level) const
   {
   BER_Object obj = decoder.get_next_object();

   const bool recurse_deeper = (m_max_depth == 0 || level < m_max_depth);

   while(obj.is_set())
      {
      const ASN1_Tag type_tag = obj.type();
      const ASN1_Tag class_tag = obj.get_class();
      const size_t length = obj.length();

      /* hack to insert the tag+length back in front of the stuff now
         that we've gotten the type info */
      std::vector<uint8_t> bits;
      DER_Encoder(bits).add_object(type_tag, class_tag, obj.bits(), obj.length());

      BER_Decoder data(bits);

      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder cons_info(obj.bits(), obj.length());

         if(recurse_deeper)
            {
            output << format(type_tag, class_tag, level, length, "");
            decode(output, cons_info, level + 1); // recurse
            }
         else
            {
            output << format(type_tag, class_tag, level, length,
                             format_bin(type_tag, class_tag, bits));
            }
         }
      else if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
         {
         bool success_parsing_cs = false;

         if(m_print_context_specific)
            {
            try
               {
               if(possibly_a_general_name(bits.data(), bits.size()))
                  {
                  output << format(type_tag, class_tag, level, level,
                                   std::string(cast_uint8_ptr_to_char(&bits[2]), bits.size() - 2));
                  success_parsing_cs = true;
                  }
               else if(recurse_deeper)
                  {
                  std::vector<uint8_t> inner_bits;
                  data.decode(inner_bits, type_tag);

                  BER_Decoder inner(inner_bits);
                  std::ostringstream inner_data;
                  decode(inner_data, inner, level + 1); // recurse
                  output << inner_data.str();
                  success_parsing_cs = true;
                  }
               }
            catch(...)
               {
               }
            }

         if(success_parsing_cs == false)
            {
            output << format(type_tag, class_tag, level, length,
                             format_bin(type_tag, class_tag, bits));
            }
         }
      else if(type_tag == OBJECT_ID)
         {
         OID oid;
         data.decode(oid);

         std::string out = OIDS::oid2str_or_empty(oid);
         if(out.empty())
            {
            out = oid.to_string();
            }
         else
            {
            out += " [" + oid.to_string() + "]";
            }

         output << format(type_tag, class_tag, level, length, out);
         }
      else if(type_tag == INTEGER || type_tag == ENUMERATED)
         {
         BigInt number;

         if(type_tag == INTEGER)
            {
            data.decode(number);
            }
         else if(type_tag == ENUMERATED)
            {
            data.decode(number, ENUMERATED, class_tag);
            }

         std::vector<uint8_t> rep = BigInt::encode(number);
         if(rep.empty()) // if zero
            rep.resize(1);

         output << format(type_tag, class_tag, level, length, hex_encode(rep));
         }
      else if(type_tag == BOOLEAN)
         {
         bool boolean;
         data.decode(boolean);
         output << format(type_tag, class_tag, level, length, (boolean ? "true" : "false"));
         }
      else if(type_tag == NULL_TAG)
         {
         output << format(type_tag, class_tag, level, length, "");
         }
      else if(type_tag == OCTET_STRING || type_tag == BIT_STRING)
         {
         std::vector<uint8_t> decoded_bits;
         data.decode(decoded_bits, type_tag);
         bool printing_octet_string_worked = false;

         if(recurse_deeper)
            {
            try
               {
               BER_Decoder inner(decoded_bits);

               std::ostringstream inner_data;
               decode(inner_data, inner, level + 1); // recurse

               output << format(type_tag, class_tag, level, length, "");
               output << inner_data.str();
               printing_octet_string_worked = true;
               }
            catch(...)
               {
               }
            }

         if(!printing_octet_string_worked)
            {
            output << format(type_tag, class_tag, level, length,
                             format_bin(type_tag, class_tag, decoded_bits));
            }
         }
      else if(ASN1_String::is_string_type(type_tag))
         {
         ASN1_String str;
         data.decode(str);
         output << format(type_tag, class_tag, level, length, str.value());
         }
      else if(type_tag == UTC_TIME || type_tag == GENERALIZED_TIME)
         {
         ASN1_Time time;
         data.decode(time);
         output << format(type_tag, class_tag, level, length, time.readable_string());
         }
      else
         {
         output << "Unknown ASN.1 tag class=" << static_cast<int>(class_tag)
                << " type=" << static_cast<int>(type_tag) << "\n";
         }

      obj = decoder.get_next_object();
      }
   }

namespace {

std::string format_type(ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if(class_tag == UNIVERSAL)
      return asn1_tag_to_string(type_tag);

   if(class_tag == CONSTRUCTED && (type_tag == SEQUENCE || type_tag == SET))
      return asn1_tag_to_string(type_tag);

   std::string name;

   if(class_tag & CONSTRUCTED)
      name += "cons ";

   name += "[" + std::to_string(type_tag) + "]";

   if(class_tag & APPLICATION)
      {
      name += " appl";
      }
   if(class_tag & CONTEXT_SPECIFIC)
      {
      name += " context";
      }

   return name;
   }

}

std::string ASN1_Pretty_Printer::format(ASN1_Tag type_tag,
                                        ASN1_Tag class_tag,
                                        size_t level,
                                        size_t length,
                                        const std::string& value) const
   {
   bool should_skip = false;

   if(value.length() > m_print_limit)
      {
      should_skip = true;
      }

   if((type_tag == OCTET_STRING || type_tag == BIT_STRING) &&
      value.length() > m_print_binary_limit)
      {
      should_skip = true;
      }

   level += m_initial_level;

   std::ostringstream oss;

   oss << "  d=" << std::setw(2) << level
       << ", l=" << std::setw(4) << length << ":"
       << std::string(level + 1, ' ') << format_type(type_tag, class_tag);

   if(value != "" && !should_skip)
      {
      const size_t current_pos = static_cast<size_t>(oss.tellp());
      const size_t spaces_to_align =
         (current_pos >= m_value_column) ? 1 : (m_value_column - current_pos);

      oss << std::string(spaces_to_align, ' ') << value;
      }

   oss << "\n";

   return oss.str();
   }

std::string ASN1_Pretty_Printer::format_bin(ASN1_Tag /*type_tag*/,
                                            ASN1_Tag /*class_tag*/,
                                            const std::vector<uint8_t>& vec) const
   {
   if(all_printable_chars(vec.data(), vec.size()))
      {
      return std::string(cast_uint8_ptr_to_char(vec.data()), vec.size());
      }
   else
      return hex_encode(vec);
   }

}
