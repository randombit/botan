/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ASN1)
   #include <botan/der_enc.h>
   #include <botan/ber_dec.h>
   #include <botan/asn1_str.h>
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

Test::Result test_asn1_utf8_ascii_parsing()
   {
      Test::Result result("ASN.1 ASCII parsing");

      try
         {
            // \x13 - ASN1 tag for 'printable string'
            // \x06 - 6 characters of payload
            // ...  - UTF-8 encoded (ASCII chars only) word 'Moscow'
            const std::string privet =
               "\x13\x06\x4D\x6F\x73\x63\x6F\x77";
            Botan::DataSource_Memory input(privet.data());
            Botan::BER_Decoder dec(input);

            Botan::ASN1_String str;
            str.decode_from(dec);

            result.test_success("No crash");
         }
      catch(const Botan::Decoding_Error &ex)
         {
            result.test_failure(ex.what());
         }

      return result;
   }

Test::Result test_asn1_utf8_parsing()
   {
      Test::Result result("ASN.1 UTF-8 parsing");

      try
         {
            // \x0C - ASN1 tag for 'UTF8 string'
            // \x0C - 12 characters of payload
            // ...  - UTF-8 encoded russian word for Moscow in cyrilic script
            const std::string privet =
               "\x0C\x0C\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
            Botan::DataSource_Memory input(privet.data());
            Botan::BER_Decoder dec(input);

            Botan::ASN1_String str;
            str.decode_from(dec);

            result.test_success("No crash");
         }
      catch(const Botan::Decoding_Error &ex)
         {
            result.test_failure(ex.what());
         }

      return result;
   }

class ASN1_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_ber_stack_recursion());
         results.push_back(test_asn1_utf8_ascii_parsing());
         results.push_back(test_asn1_utf8_parsing());

         return results;
         }
   };

BOTAN_REGISTER_TEST("asn1", ASN1_Tests);

#endif

}

