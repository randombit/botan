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
#include <botan/charset.h>

#include <iomanip>
#include <sstream>
#include <ctype.h>

// Set this if your terminal understands UTF-8; otherwise output is in Latin-1
#define UTF8_TERMINAL 1

namespace Botan_CLI {

namespace {

std::string url_encode(const std::vector<uint8_t>& in)
   {
   std::ostringstream out;

   size_t unprintable = 0;

   for(size_t i = 0; i != in.size(); ++i)
      {
      const int c = in[i];
      if(::isprint(c))
         {
         out << static_cast<char>(c);
         }
      else
         {
         out << "%" << std::hex << static_cast<int>(c) << std::dec;
         ++unprintable;
         }
      }

   if(unprintable >= in.size() / 4)
      {
      return Botan::hex_encode(in);
      }

   return out.str();
   }

void emit(std::ostream& out,
          const std::string& type,
          size_t level, size_t length,
          const std::string& value = "")
   {
   // TODO make these configurable
   const size_t LIMIT = 4 * 1024;
   const size_t BIN_LIMIT = 1024;

   std::streampos starting_pos = out.tellp();

   out << "  d=" << std::setw(2) << level
       << ", l=" << std::setw(4) << length << ": ";

   for(size_t i = 0; i != level; ++i)
      {
      out << ' ';
      }

   out << type;

   bool should_skip = false;

   if(value.length() > LIMIT)
      {
      should_skip = true;
      }

   if((type == "OCTET STRING" || type == "BIT STRING") && value.length() > BIN_LIMIT)
      {
      should_skip = true;
      }

   if(value != "" && !should_skip)
      {
      while(out.tellp() - starting_pos < 50)
         {
         out << ' ';
         }

      out << value;
      }

   out << "\n";
   }

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

void decode(std::ostream& output,
            Botan::BER_Decoder& decoder,
            size_t level)
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
#if 0
         std::vector<uint8_t> bits;
         data.decode(out, bits, type_tag);

         try
            {
            Botan::BER_Decoder inner(bits);
            decode(output, inner, level + 1); // recurse
            }
         catch(...)
            {
            emit(output, "[" + std::to_string(type_tag) + "]", level, length, url_encode(bits));
            }
#else
         emit(output, "[" + std::to_string(type_tag) + "]", level, length, url_encode(bits));
#endif
         }
      else if(type_tag == Botan::OBJECT_ID)
         {
         Botan::OID oid;
         data.decode(oid);

         std::string out = Botan::OIDS::lookup(oid);
         if(out != oid.as_string())
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
      else if(type_tag == Botan::OCTET_STRING)
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
            emit(output, type_name(type_tag), level, length, url_encode(decoded_bits));
            }
         }
      else if(type_tag == Botan::BIT_STRING)
         {
         std::vector<uint8_t> decoded_bits;
         data.decode(decoded_bits, type_tag);

         std::vector<bool> bit_set;

         for(size_t i = 0; i != decoded_bits.size(); ++i)
            {
            for(size_t j = 0; j != 8; ++j)
               {
               const bool bit = static_cast<bool>((decoded_bits[decoded_bits.size() - i - 1] >> (7 - j)) & 1);
               bit_set.push_back(bit);
               }
            }

         std::string bit_str;
         for(size_t i = 0; i != bit_set.size(); ++i)
            {
            bool the_bit = bit_set[bit_set.size() - i - 1];

            if(!the_bit && bit_str.size() == 0)
               {
               continue;
               }
            bit_str += (the_bit ? "1" : "0");
            }

         emit(output, type_name(type_tag), level, length, bit_str);
         }
      else if(type_tag == Botan::PRINTABLE_STRING ||
              type_tag == Botan::NUMERIC_STRING ||
              type_tag == Botan::IA5_STRING ||
              type_tag == Botan::T61_STRING ||
              type_tag == Botan::VISIBLE_STRING ||
              type_tag == Botan::UTF8_STRING ||
              type_tag == Botan::BMP_STRING)
         {
         Botan::ASN1_String str;
         data.decode(str);
         if(UTF8_TERMINAL)
            {
            emit(output, type_name(type_tag), level, length,
                 Botan::Charset::transcode(str.iso_8859(),
                                           Botan::UTF8_CHARSET,
                                           Botan::LATIN1_CHARSET));
            }
         else
            {
            emit(output, type_name(type_tag), level, length, str.iso_8859());
            }
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

std::string format_asn1(const uint8_t in[], size_t len)
   {
   std::ostringstream out;
   Botan::BER_Decoder dec(in, len);
   decode(out, dec, 0);
   return out.str();
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

         output() << format_asn1(contents.data(), contents.size());
         }
   };

BOTAN_REGISTER_COMMAND("asn1print", ASN1_Printer);

}

#endif // BOTAN_HAS_ASN1 && BOTAN_HAS_PEM_CODEC
