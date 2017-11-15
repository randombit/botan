/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ASN1) && defined(BOTAN_HAS_PEM_CODEC)

#include <botan/bigint.h>
#include <botan/hex.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_time.h>
#include <botan/asn1_str.h>
#include <botan/oids.h>
#include <botan/pem.h>

#include <iomanip>
#include <sstream>
#include <cctype>

namespace Botan_CLI {

namespace {

std::string type_name(Botan::ASN1_Tag type)
   {
   switch(type)
      {
      case Botan::PRINTABLE_STRING:
         return "PRINTABLE STRING";

      case Botan::NUMERIC_STRING:
         return "NUMERIC STRING";

      case Botan::IA5_STRING:
         return "IA5 STRING";

      case Botan::T61_STRING:
         return "T61 STRING";

      case Botan::UTF8_STRING:
         return "UTF8 STRING";

      case Botan::VISIBLE_STRING:
         return "VISIBLE STRING";

      case Botan::BMP_STRING:
         return "BMP STRING";

      case Botan::UTC_TIME:
         return "UTC TIME";

      case Botan::GENERALIZED_TIME:
         return "GENERALIZED TIME";

      case Botan::OCTET_STRING:
         return "OCTET STRING";

      case Botan::BIT_STRING:
         return "BIT STRING";

      case Botan::ENUMERATED:
         return "ENUMERATED";

      case Botan::INTEGER:
         return "INTEGER";

      case Botan::NULL_TAG:
         return "NULL";

      case Botan::OBJECT_ID:
         return "OBJECT";

      case Botan::BOOLEAN:
         return "BOOLEAN";

      default:
         return "TAG(" + std::to_string(static_cast<size_t>(type)) + ")";
      }
   }

class ASN1_Pretty_Printer
   {
   public:
      ASN1_Pretty_Printer(size_t print_limit = 256,
                          size_t print_binary_limit = 256,
                          bool print_context_specific = true,
                          size_t initial_level = 0,
                          size_t value_column = 50) :
         m_print_limit(print_limit),
         m_print_binary_limit(print_binary_limit),
         m_initial_level(initial_level),
         m_value_column(value_column),
         m_print_context_specific(print_context_specific)
         {}

      void print_to_stream(std::ostream& out,
                           const uint8_t in[],
                           size_t len) const;

      std::string print(const uint8_t in[], size_t len) const;

      template<typename Alloc>
      std::string print(const std::vector<uint8_t, Alloc>& vec) const
         {
         return print(vec.data(), vec.size());
         }

   private:
      void emit(std::ostream& out,
                const std::string& type,
                size_t level, size_t length,
                const std::string& value = "") const;

      void decode(std::ostream& output,
                  Botan::BER_Decoder& decoder,
                  size_t level) const;

      std::string format_binary(const std::vector<uint8_t>& in) const;

      const size_t m_print_limit;
      const size_t m_print_binary_limit;
      const size_t m_initial_level;
      const size_t m_value_column;
      const bool m_print_context_specific;
   };

std::string ASN1_Pretty_Printer::print(const uint8_t in[], size_t len) const
   {
   std::ostringstream out;
   print_to_stream(out, in, len);
   return out.str();
   }

void ASN1_Pretty_Printer::print_to_stream(std::ostream& out,
                                          const uint8_t in[],
                                          size_t len) const
   {
   Botan::BER_Decoder dec(in, len);
   this->decode(out, dec, m_initial_level);
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
            return Botan::hex_encode(in);
            }
         }
      }

   return out.str();
   }

void ASN1_Pretty_Printer::emit(std::ostream& out,
                               const std::string& type,
                               size_t level, size_t length,
                               const std::string& value) const
   {
   std::streampos starting_pos = out.tellp();

   out << "  d=" << std::setw(2) << level
       << ", l=" << std::setw(4) << length << ": ";

   for(size_t i = 0; i != level; ++i)
      {
      out << ' ';
      }

   out << type;

   bool should_skip = false;

   if(value.length() > m_print_limit)
      {
      should_skip = true;
      }

   if((type == "OCTET STRING" || type == "BIT STRING") && value.length() > m_print_binary_limit)
      {
      should_skip = true;
      }

   if(value != "" && !should_skip)
      {
      while(static_cast<size_t>(out.tellp() - starting_pos) < m_value_column)
         {
         out << ' ';
         }

      out << value;
      }

   out << "\n";
   }

void ASN1_Pretty_Printer::decode(std::ostream& output,
                                 Botan::BER_Decoder& decoder,
                                 size_t level) const
   {
   Botan::BER_Object obj = decoder.get_next_object();

   while(obj.type_tag != Botan::NO_OBJECT)
      {
      const Botan::ASN1_Tag type_tag = obj.type_tag;
      const Botan::ASN1_Tag class_tag = obj.class_tag;
      const size_t length = obj.value.size();

      /* hack to insert the tag+length back in front of the stuff now
         that we've gotten the type info */
      Botan::DER_Encoder encoder;
      encoder.add_object(type_tag, class_tag, obj.value);
      std::vector<uint8_t> bits = encoder.get_contents_unlocked();

      Botan::BER_Decoder data(bits);

      if(class_tag & Botan::CONSTRUCTED)
         {
         Botan::BER_Decoder cons_info(obj.value);
         if(type_tag == Botan::SEQUENCE)
            {
            emit(output, "SEQUENCE", level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         else if(type_tag == Botan::SET)
            {
            emit(output, "SET", level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         else
            {
            std::string name;

            if((class_tag & Botan::APPLICATION) || (class_tag & Botan::CONTEXT_SPECIFIC))
               {
               name = "cons [" + std::to_string(type_tag) + "]";

               if(class_tag & Botan::APPLICATION)
                  {
                  name += " appl";
                  }
               if(class_tag & Botan::CONTEXT_SPECIFIC)
                  {
                  name += " context";
                  }
               }
            else
               {
               name = type_name(type_tag) + " (cons)";
               }

            emit(output, name, level, length);
            decode(output, cons_info, level + 1); // recurse
            }
         }
      else if((class_tag & Botan::APPLICATION) || (class_tag & Botan::CONTEXT_SPECIFIC))
         {
         if(m_print_context_specific)
            {
            std::vector<uint8_t> bits;
            data.decode(bits, type_tag);

            try
               {
               Botan::BER_Decoder inner(bits);
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
      else if(type_tag == Botan::OBJECT_ID)
         {
         Botan::OID oid;
         data.decode(oid);

         std::string out = Botan::OIDS::lookup(oid);
         if(out.empty())
            {
            out = oid.as_string();
            }
         else
            {
            out += " [" + oid.as_string() + "]";
            }

         emit(output, type_name(type_tag), level, length, out);
         }
      else if(type_tag == Botan::INTEGER || type_tag == Botan::ENUMERATED)
         {
         Botan::BigInt number;

         if(type_tag == Botan::INTEGER)
            {
            data.decode(number);
            }
         else if(type_tag == Botan::ENUMERATED)
            {
            data.decode(number, Botan::ENUMERATED, class_tag);
            }

         std::vector<uint8_t> rep;

         /* If it's small, it's probably a number, not a hash */
         if(number.bits() <= 20)
            {
            rep = Botan::BigInt::encode(number, Botan::BigInt::Decimal);
            }
         else
            {
            rep = Botan::BigInt::encode(number, Botan::BigInt::Hexadecimal);
            }

         std::string str;
         for(size_t i = 0; i != rep.size(); ++i)
            {
            str += static_cast<char>(rep[i]);
            }

         emit(output, type_name(type_tag), level, length, str);
         }
      else if(type_tag == Botan::BOOLEAN)
         {
         bool boolean;
         data.decode(boolean);
         emit(output, type_name(type_tag), level, length, (boolean ? "true" : "false"));
         }
      else if(type_tag == Botan::NULL_TAG)
         {
         emit(output, type_name(type_tag), level, length);
         }
      else if(type_tag == Botan::OCTET_STRING || type_tag == Botan::BIT_STRING)
         {
         std::vector<uint8_t> decoded_bits;
         data.decode(decoded_bits, type_tag);

         try
            {
            Botan::BER_Decoder inner(decoded_bits);
            decode(output, inner, level + 1);
            }
         catch(...)
            {
            emit(output, type_name(type_tag), level, length, format_binary(decoded_bits));
            }
         }
      else if(Botan::ASN1_String::is_string_type(type_tag))
         {
         Botan::ASN1_String str;
         data.decode(str);
         emit(output, type_name(type_tag), level, length, str.value());
         }
      else if(type_tag == Botan::UTC_TIME || type_tag == Botan::GENERALIZED_TIME)
         {
         Botan::X509_Time time;
         data.decode(time);
         emit(output, type_name(type_tag), level, length, time.readable_string());
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

class ASN1_Printer final : public Command
   {
   public:
      ASN1_Printer() : Command("asn1print --pem file") {}

      void go() override
         {
         const std::string input = get_arg("file");

         std::vector<uint8_t> contents;

         if(flag_set("pem"))
            {
            std::string pem_label;
            contents = unlock(Botan::PEM_Code::decode(slurp_file_as_str(input), pem_label));
            }
         else
            {
            contents = slurp_file(input);
            }

         // TODO make these configurable
         const size_t LIMIT = 4 * 1024;
         const size_t BIN_LIMIT = 1024;
         const bool PRINT_CONTEXT_SPECIFIC = true;

         ASN1_Pretty_Printer printer(LIMIT, BIN_LIMIT, PRINT_CONTEXT_SPECIFIC);
         output() << printer.print(contents);
         }
   };

BOTAN_REGISTER_COMMAND("asn1print", ASN1_Printer);

}

#endif // BOTAN_HAS_ASN1 && BOTAN_HAS_PEM_CODEC
