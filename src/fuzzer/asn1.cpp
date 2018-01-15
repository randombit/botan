/*
* (C) 2016,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/asn1_print.h>
#include <fstream>

class ASN1_Parser final : public Botan::ASN1_Formatter
   {
   public:
      ASN1_Parser() : Botan::ASN1_Formatter(true, 64) {}

   protected:
      std::string format(Botan::ASN1_Tag, Botan::ASN1_Tag, size_t, size_t,
                         const std::string&) const override
         {
         return "";
         }

      std::string format_bin(Botan::ASN1_Tag, Botan::ASN1_Tag,
                             const std::vector<uint8_t>&) const override
         {
         return "";
         }
   };

void fuzz(const uint8_t in[], size_t len)
   {
   try
      {
      /*
      * Here we use an uninitialized ofstream so the fuzzer doesn't spend time
      * on actual output formatting, no memory is allocated, etc.
      */
      std::ofstream out;
      ASN1_Parser printer;
      printer.print_to_stream(out, in, len);
      }
   catch(Botan::Exception& e) { }
   }
