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
#include <botan/asn1_time.h>
#include <botan/asn1_str.h>
#include <botan/oids.h>
#include <iomanip>
#include <sstream>
#include <cctype>

namespace Botan {

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

   while(obj.type_tag != NO_OBJECT)
      {
      const ASN1_Tag type_tag = obj.type_tag;
      const ASN1_Tag class_tag = obj.class_tag;
      const size_t length = obj.value.size();

      /* hack to insert the tag+length back in front of the stuff now
         that we've gotten the type info */
      DER_Encoder encoder;
      encoder.add_object(type_tag, class_tag, obj.value);
      const std::vector<uint8_t> bits = encoder.get_contents_unlocked();

      BER_Decoder data(bits);

      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder cons_info(obj.value);
         output << format(type_tag, class_tag, level, length, "");
         decode(output, cons_info, level + 1); // recurse
         }
      else if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
         {
         if(m_print_context_specific)
            {
            try
               {
               std::vector<uint8_t> inner_bits;
               data.decode(inner_bits, type_tag);
               BER_Decoder inner(inner_bits);

               std::ostringstream inner_data;
               decode(inner_data, inner, level + 1); // recurse
               output << inner_data.str();
               }
            catch(...)
               {
               output << format(type_tag, class_tag, level, length,
                                format_bin(type_tag, class_tag, bits));
               }
            }
         else
            {
            output << format(type_tag, class_tag, level, length,
                             format_bin(type_tag, class_tag, bits));
            }
         }
      else if(type_tag == OBJECT_ID)
         {
         OID oid;
         data.decode(oid);

         std::string out = OIDS::lookup(oid);
         if(out.empty())
            {
            out = oid.as_string();
            }
         else
            {
            out += " [" + oid.as_string() + "]";
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

         const std::vector<uint8_t> rep = BigInt::encode(number, BigInt::Hexadecimal);

         std::string str;
         for(size_t i = 0; i != rep.size(); ++i)
            {
            str += static_cast<char>(rep[i]);
            }

         output << format(type_tag, class_tag, level, length, str);
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

         try
            {
            BER_Decoder inner(decoded_bits);

            std::ostringstream inner_data;
            decode(inner_data, inner, level + 1); // recurse

            output << format(type_tag, class_tag, level, length, "");
            output << inner_data.str();
            }
         catch(...)
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
         X509_Time time;
         data.decode(time);
         output << format(type_tag, class_tag, level, length, time.readable_string());
         }
      else
         {
         output << "Unknown ASN.1 tag class=" << static_cast<int>(class_tag)
                << " type=" << static_cast<int>(type_tag) << "\n";;
         }

      obj = decoder.get_next_object();
      }
   }

namespace {

std::string format_type(ASN1_Tag type_tag, ASN1_Tag class_tag)
   {
   if((class_tag & CONSTRUCTED) && ((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC)))
      {
      std::string name = "cons [" + std::to_string(type_tag) + "]";

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
   else
      {
      return asn1_tag_to_string(type_tag);
      }
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
   const size_t unprintable_bound = vec.size() / 4;
   size_t unprintable = 0;

   std::ostringstream out;

   for(size_t i = 0; i != vec.size(); ++i)
      {
      const int c = vec[i];
      if(std::isalnum(c))
         {
         out << static_cast<char>(c);
         }
      else
         {
         out << "x" << std::hex << static_cast<int>(c) << std::dec;
         ++unprintable;
         if(unprintable >= unprintable_bound)
            {
            return hex_encode(vec);
            }
         }
      }

   return out.str();
   }

}
