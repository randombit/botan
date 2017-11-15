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

std::string ASN1_Pretty_Printer::print(const uint8_t in[], size_t len) const
   {
   std::ostringstream output;
   print_to_stream(output, in, len);
   return output.str();
   }

void ASN1_Pretty_Printer::print_to_stream(std::ostream& output,
                                          const uint8_t in[],
                                          size_t len) const
   {
   BER_Decoder dec(in, len);
   decode(output, dec, m_initial_level);
   }

std::string ASN1_Pretty_Printer::format_binary(const std::vector<uint8_t>& in) const
   {
   std::ostringstream out;

   size_t unprintable = 0;

   for(size_t i = 0; i != in.size(); ++i)
      {
      const int c = in[i];
      if(std::isalnum(c))
         {
         out << static_cast<char>(c);
         }
      else
         {
         out << "%" << std::hex << static_cast<int>(c) << std::dec;
         ++unprintable;
         if(unprintable >= in.size() / 4)
            {
            return hex_encode(in);
            }
         }
      }

   return out.str();
   }

void ASN1_Pretty_Printer::emit(std::ostream& output,
                               const std::string& type,
                               size_t level, size_t length,
                               const std::string& value) const
   {
   std::ostringstream oss;

   oss << "  d=" << std::setw(2) << level
       << ", l=" << std::setw(4) << length << ":"
       << std::string(level + 1, ' ') << type;

   bool should_skip = false;

   if(value.length() > m_print_limit)
      {
      should_skip = true;
      }

   if((type == "OCTET STRING" || type == "BIT STRING") && value.length() > m_print_binary_limit)
      {
      should_skip = true;
      }

   const std::string s = oss.str();

   output << s;

   if(value != "" && !should_skip)
      {
      const size_t spaces_to_align =
         (s.size() >= m_value_column) ? 1 : (m_value_column - s.size());

      output << std::string(spaces_to_align, ' ') << value;
      }

   output << "\n";
   }

void ASN1_Pretty_Printer::decode(std::ostream& output,
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
      std::vector<uint8_t> bits = encoder.get_contents_unlocked();

      BER_Decoder data(bits);

      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder cons_info(obj.value);
         if(type_tag == SEQUENCE)
            {
            emit(output, "SEQUENCE", level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         else if(type_tag == SET)
            {
            emit(output, "SET", level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         else
            {
            std::string name;

            if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
               {
               name = "cons [" + std::to_string(type_tag) + "]";

               if(class_tag & APPLICATION)
                  {
                  name += " appl";
                  }
               if(class_tag & CONTEXT_SPECIFIC)
                  {
                  name += " context";
                  }
               }
            else
               {
               name = asn1_tag_to_string(type_tag) + " (cons)";
               }

            emit(output, name, level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         }
      else if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
         {
         if(m_print_context_specific)
            {
            std::vector<uint8_t> bits;
            data.decode(bits, type_tag);

            try
               {
               BER_Decoder inner(bits);
               decode(output, inner, level + 1); // recurse
               }
            catch(...)
               {
               emit(output, "[" + std::to_string(type_tag) + "]", level, length, format_binary(bits));
               }
            }
         else
            {
            emit(output, "[" + std::to_string(type_tag) + "]", level, length, format_binary(bits));
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

         emit(output, asn1_tag_to_string(type_tag), level, length, out);
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

         std::vector<uint8_t> rep;

         /* If it's small, it's probably a number, not a hash */
         if(number.bits() <= 20)
            {
            rep = BigInt::encode(number, BigInt::Decimal);
            }
         else
            {
            rep = BigInt::encode(number, BigInt::Hexadecimal);
            }

         std::string str;
         for(size_t i = 0; i != rep.size(); ++i)
            {
            str += static_cast<char>(rep[i]);
            }

         emit(output, asn1_tag_to_string(type_tag), level, length, str);
         }
      else if(type_tag == BOOLEAN)
         {
         bool boolean;
         data.decode(boolean);
         emit(output, asn1_tag_to_string(type_tag), level, length, (boolean ? "true" : "false"));
         }
      else if(type_tag == NULL_TAG)
         {
         emit(output, asn1_tag_to_string(type_tag), level, length);
         }
      else if(type_tag == OCTET_STRING || type_tag == BIT_STRING)
         {
         std::vector<uint8_t> decoded_bits;
         data.decode(decoded_bits, type_tag);

         try
            {
            BER_Decoder inner(decoded_bits);
            decode(output, inner, level + 1);
            }
         catch(...)
            {
            emit(output, asn1_tag_to_string(type_tag), level, length, format_binary(decoded_bits));
            }
         }
      else if(ASN1_String::is_string_type(type_tag))
         {
         ASN1_String str;
         data.decode(str);
         emit(output, asn1_tag_to_string(type_tag), level, length, str.value());
         }
      else if(type_tag == UTC_TIME || type_tag == GENERALIZED_TIME)
         {
         X509_Time time;
         data.decode(time);
         emit(output, asn1_tag_to_string(type_tag), level, length, time.readable_string());
         }
      else
         {
         output << "Unknown ASN.1 tag class=" << static_cast<int>(class_tag)
                << " type=" << static_cast<int>(type_tag) << "\n";;
         }

      obj = decoder.get_next_object();
      }
   }

}
