/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ASN1)
   #include <botan/der_enc.h>
   #include <botan/ber_dec.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_ASN1)

namespace {

Test::Result test_ber_stack_recursion()
   {
   Test::Result result("BER stack recursion");

   // OSS-Fuzz #813 GitHub #989

   try
      {
      const std::vector<uint8_t> in(10000000, 0);
      Botan::DataSource_Memory input(in.data(), in.size());
      Botan::BER_Decoder dec(input);

      while(dec.more_items())
         {
         Botan::BER_Object obj;
         dec.get_next(obj);
         }
      }
   catch(Botan::Decoding_Error&)
      {
      }

   result.test_success("No crash");

   return result;
   }

}

class ASN1_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_ber_stack_recursion());

         return results;
         }
   };

BOTAN_REGISTER_TEST("asn1", ASN1_Tests);

#endif

}

