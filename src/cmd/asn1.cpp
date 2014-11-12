#include "apps.h"

#include <botan/bigint.h>
#include <botan/hex.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_time.h>
#include <botan/asn1_str.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <botan/charset.h>
using namespace Botan;

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctype.h>

// Set this if your terminal understands UTF-8; otherwise output is in Latin-1
#define UTF8_TERMINAL 1

/*
   What level the outermost layer of stuff is at. Probably 0 or 1; asn1parse
   uses 0 as the outermost, while 1 makes more sense to me. 2+ doesn't make
   much sense at all.
*/
#define INITIAL_LEVEL 0

namespace {

std::string url_encode(const std::vector<byte>& in)
   {
   std::ostringstream out;

   size_t unprintable = 0;

   for(size_t i = 0; i != in.size(); ++i)
      {
      const int c = in[i];
      if(::isprint(c))
         out << static_cast<char>(c);
      else
         {
         out << "%" << std::hex << static_cast<int>(c) << std::dec;
         ++unprintable;
         }
      }

   if(unprintable >= in.size() / 4)
      return hex_encode(in);

   return out.str();
   }

void emit(const std::string& type, size_t level, size_t length, const std::string& value = "")
   {
   const size_t LIMIT = 4*1024;
   const size_t BIN_LIMIT = 1024;

   std::ostringstream out;

   out << "  d=" << std::setw(2) << level
       << ", l=" << std::setw(4) << length << ": ";

   for(size_t i = INITIAL_LEVEL; i != level; ++i)
      out << ' ';

   out << type;

   bool should_skip = false;

   if(value.length() > LIMIT)
      should_skip = true;

   if((type == "OCTET STRING" || type == "BIT STRING") && value.length() > BIN_LIMIT)
      should_skip = true;

   if(value != "" && !should_skip)
      {
      if(out.tellp() % 2 == 0) out << ' ';

      while(out.tellp() < 50) out << ' ';

      out << value;
      }

   std::cout << out.str() << "\n";
   }

std::string type_name(ASN1_Tag type)
   {
   if(type == PRINTABLE_STRING) return "PRINTABLE STRING";
   if(type == NUMERIC_STRING)   return "NUMERIC STRING";
   if(type == IA5_STRING)       return "IA5 STRING";
   if(type == T61_STRING)       return "T61 STRING";
   if(type == UTF8_STRING)      return "UTF8 STRING";
   if(type == VISIBLE_STRING)   return "VISIBLE STRING";
   if(type == BMP_STRING)       return "BMP STRING";

   if(type == UTC_TIME)         return "UTC TIME";
   if(type == GENERALIZED_TIME) return "GENERALIZED TIME";

   if(type == OCTET_STRING)     return "OCTET STRING";
   if(type == BIT_STRING)       return "BIT STRING";

   if(type == ENUMERATED)       return "ENUMERATED";
   if(type == INTEGER)          return "INTEGER";
   if(type == NULL_TAG)         return "NULL";
   if(type == OBJECT_ID)        return "OBJECT";
   if(type == BOOLEAN)          return "BOOLEAN";
   return "(UNKNOWN)";
   }

void decode(BER_Decoder& decoder, size_t level)
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
      std::vector<byte> bits = encoder.get_contents_unlocked();

      BER_Decoder data(bits);

      if(class_tag & CONSTRUCTED)
         {
         BER_Decoder cons_info(obj.value);
         if(type_tag == SEQUENCE)
            {
            emit("SEQUENCE", level, length);
            decode(cons_info, level+1);
            }
         else if(type_tag == SET)
            {
            emit("SET", level, length);
            decode(cons_info, level+1);
            }
         else
            {
            std::string name;

            if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
               {
               name = "cons [" + std::to_string(type_tag) + "]";

               if(class_tag & APPLICATION)
                  name += " appl";
               if(class_tag & CONTEXT_SPECIFIC)
                  name += " context";
               }
            else
               name = type_name(type_tag) + " (cons)";

            emit(name, level, length);
            decode(cons_info, level+1);
            }
         }
      else if((class_tag & APPLICATION) || (class_tag & CONTEXT_SPECIFIC))
         {
#if 0
         std::vector<byte> bits;
         data.decode(bits, type_tag);

         try
            {
            BER_Decoder inner(bits);
            decode(inner, level + 1);
            }
         catch(...)
            {
            emit("[" + std::to_string(type_tag) + "]", level, length,
                 url_encode(bits));
            }
#else
         emit("[" + std::to_string(type_tag) + "]", level, length,
              url_encode(bits));
#endif
         }
      else if(type_tag == OBJECT_ID)
         {
         OID oid;
         data.decode(oid);

         std::string out = OIDS::lookup(oid);
         if(out != oid.as_string())
            out += " [" + oid.as_string() + "]";

         emit(type_name(type_tag), level, length, out);
         }
      else if(type_tag == INTEGER || type_tag == ENUMERATED)
         {
         BigInt number;

         if(type_tag == INTEGER)
            data.decode(number);
         else if(type_tag == ENUMERATED)
            data.decode(number, ENUMERATED, class_tag);

         std::vector<byte> rep;

         /* If it's small, it's probably a number, not a hash */
         if(number.bits() <= 20)
            rep = BigInt::encode(number, BigInt::Decimal);
         else
            rep = BigInt::encode(number, BigInt::Hexadecimal);

         std::string str;
         for(size_t i = 0; i != rep.size(); ++i)
            str += static_cast<char>(rep[i]);

         emit(type_name(type_tag), level, length, str);
         }
      else if(type_tag == BOOLEAN)
         {
         bool boolean;
         data.decode(boolean);
         emit(type_name(type_tag),
              level, length, (boolean ? "true" : "false"));
         }
      else if(type_tag == NULL_TAG)
         {
         emit(type_name(type_tag), level, length);
         }
      else if(type_tag == OCTET_STRING)
         {
         std::vector<byte> bits;
         data.decode(bits, type_tag);

         try
            {
            BER_Decoder inner(bits);
            decode(inner, level + 1);
            }
         catch(...)
            {
            emit(type_name(type_tag), level, length,
                 url_encode(bits));
            }
         }
      else if(type_tag == BIT_STRING)
         {
         std::vector<byte> bits;
         data.decode(bits, type_tag);

         std::vector<bool> bit_set;

         for(size_t i = 0; i != bits.size(); ++i)
            for(size_t j = 0; j != 8; ++j)
               {
               const bool bit = static_cast<bool>((bits[bits.size()-i-1] >> (7-j)) & 1);
               bit_set.push_back(bit);
               }

         std::string bit_str;
         for(size_t i = 0; i != bit_set.size(); ++i)
            {
            bool the_bit = bit_set[bit_set.size()-i-1];

            if(!the_bit && bit_str.size() == 0)
               continue;
            bit_str += (the_bit ? "1" : "0");
            }

         emit(type_name(type_tag), level, length, bit_str);
         }
      else if(type_tag == PRINTABLE_STRING ||
              type_tag == NUMERIC_STRING ||
              type_tag == IA5_STRING ||
              type_tag == T61_STRING ||
              type_tag == VISIBLE_STRING ||
              type_tag == UTF8_STRING ||
              type_tag == BMP_STRING)
         {
         ASN1_String str;
         data.decode(str);
         if(UTF8_TERMINAL)
            emit(type_name(type_tag), level, length,
                 Charset::transcode(str.iso_8859(),
                                    LATIN1_CHARSET, UTF8_CHARSET));
         else
            emit(type_name(type_tag), level, length, str.iso_8859());
         }
      else if(type_tag == UTC_TIME || type_tag == GENERALIZED_TIME)
         {
         X509_Time time;
         data.decode(time);
         emit(type_name(type_tag), level, length, time.readable_string());
         }
      else
         {
         std::cout << "Unknown ASN.1 tag class="
                   << static_cast<int>(class_tag)
                   << " type="
                   << static_cast<int>(type_tag) << "\n";
         }

      obj = decoder.get_next_object();
      }
   }

int asn1(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " <file>\n";
      return 1;
      }

   try {
      DataSource_Stream in(argv[1]);

      if(!PEM_Code::matches(in))
         {
         BER_Decoder decoder(in);
         decode(decoder, INITIAL_LEVEL);
         }
      else
         {
         std::string label; // ignored
         BER_Decoder decoder(PEM_Code::decode(in, label));
         decode(decoder, INITIAL_LEVEL);
         }
   }
   catch(std::exception& e)
      {
      std::cout << "Error: " << e.what() << "\n";
      return 2;
      }

   return 0;
   }

REGISTER_APP(asn1);

}
