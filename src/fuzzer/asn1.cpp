/*
* (C) 2016,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/asn1_print.h>
#include <botan/assert.h>
#include <fstream>

class ASN1_Parser final : public Botan::ASN1_Formatter {
   public:
      ASN1_Parser() : Botan::ASN1_Formatter(true, 64) {}

   protected:
      std::string format(Botan::ASN1_Type type,
                         Botan::ASN1_Class klass,
                         size_t level,
                         size_t length,
                         std::string_view value) const override {
         BOTAN_UNUSED(type, klass, level, length, value);
         return "";
      }

      std::string format_bin(Botan::ASN1_Type type,
                             Botan::ASN1_Class klass,
                             const std::vector<uint8_t>& value) const override {
         BOTAN_UNUSED(type, klass, value);
         return "";
      }

      std::string format_bn(const Botan::BigInt& bn) const override {
         BOTAN_UNUSED(bn);
         return "";
      }
};

void fuzz(std::span<const uint8_t> in) {
   try {
      /*
      * Here we use an uninitialized ofstream so the fuzzer doesn't spend time
      * on actual output formatting, no memory is allocated, etc.
      */
      std::ofstream out;
      const ASN1_Parser printer;
      printer.print_to_stream(out, in.data(), in.size());
   } catch(Botan::Exception& e) {}
}
