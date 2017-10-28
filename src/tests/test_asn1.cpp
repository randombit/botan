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
      const std::string moscow =
         "\x13\x06\x4D\x6F\x73\x63\x6F\x77";
      const std::string moscow_plain = "Moscow";
      Botan::DataSource_Memory input(moscow.data());
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_eq("value()", str.value(), moscow_plain);
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
      // ...  - UTF-8 encoded russian word for Moscow in cyrillic script
      const std::string moscow =
         "\x0C\x0C\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      const std::string moscow_plain =
         "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      Botan::DataSource_Memory input(moscow.data());
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_eq("value()", str.value(), moscow_plain);
      }
   catch(const Botan::Decoding_Error &ex)
      {
      result.test_failure(ex.what());
      }

   return result;
   }

Test::Result test_asn1_ucs2_parsing()
   {
   Test::Result result("ASN.1 BMP string (UCS-2) parsing");

   try
      {
      // \x1E     - ASN1 tag for 'BMP (UCS-2) string'
      // \x0E     - 14 characters of payload (includes BOM)
      // \xFF\xFE - Byte Order Mark (BOM)
      // ...      - UCS-2 encoding for Moscow in cyrillic script
      const std::string moscow =
         "\x1E\x0E\xFF\xFE\x1C\x04\x3E\x04"
         "\x41\x04\x3A\x04\x32\x04\x30\x04";
      const std::string moscow_plain =  // with BOM (EF BB BF)
         "\xEF\xBB\xBF\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      Botan::DataSource_Memory input(moscow.data());
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_eq("value()", str.value(), moscow_plain);
      }
   catch(const Botan::Decoding_Error &ex)
      {
         result.test_failure(ex.what());
      }

   return result;
   }

Test::Result test_asn1_ucs4_parsing()
   {
   Test::Result result("ASN.1 universal string (UTF-32 LE) parsing");

   try
      {
      // \x1C - ASN1 tag for 'universal string'
      // \x1C - 28 characters of payload (with BOM - FF FE 00 00)
      // ...  - UTF-32 LE encoding for Moscow in cyrillic script
      const Botan::byte moscow[] =
         "\x1C\x1C\xFF\xFE\x00\x00\x1C\x04\x00\x00\x3E\x04\x00\x00\x41"
         "\x04\x00\x00\x3A\x04\x00\x00\x32\x04\x00\x00\x30\x04\x00\x00";
      const std::string moscow_plain =  // with BOM (EF BB BF)
         "\xEF\xBB\xBF\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      Botan::DataSource_Memory input(moscow, sizeof(moscow));
      Botan::BER_Decoder dec(input);

      Botan::ASN1_String str;
      str.decode_from(dec);

      result.test_eq("value()", str.value(), moscow_plain);
      }
   catch(const Botan::Decoding_Error &ex)
      {
      result.test_failure(ex.what());
      }

   return result;
   }

Test::Result test_asn1_ascii_encoding()
   {
   Test::Result result("ASN.1 ASCII encoding");

   try
      {
      // UTF-8 encoded (ASCII chars only) word 'Moscow'
      const std::string moscow =
         "\x4D\x6F\x73\x63\x6F\x77";
      Botan::ASN1_String str(moscow);

      Botan::DER_Encoder enc;

      str.encode_into(enc);
      auto encodingResult = enc.get_contents();

      // \x13 - ASN1 tag for 'printable string'
      // \x06 - 6 characters of payload
      const auto moscowEncoded = Botan::hex_decode("13064D6F73636F77");
      result.test_eq("encoding result", encodingResult, moscowEncoded);

      result.test_success("No crash");
      }
   catch(const std::exception &ex)
      {
      result.test_failure(ex.what());
      }

   return result;
   }

Test::Result test_asn1_utf8_encoding()
   {
   Test::Result result("ASN.1 UTF-8 encoding");

   try
      {
      // UTF-8 encoded russian word for Moscow in cyrillic script
      const std::string moscow =
         "\xD0\x9C\xD0\xBE\xD1\x81\xD0\xBA\xD0\xB2\xD0\xB0";
      Botan::ASN1_String str(moscow);

      Botan::DER_Encoder enc;

      str.encode_into(enc);
      auto encodingResult = enc.get_contents();

      // \x0C - ASN1 tag for 'UTF8 string'
      // \x0C - 12 characters of payload
      const auto moscowEncoded =
         Botan::hex_decode("0C0CD09CD0BED181D0BAD0B2D0B0");
      result.test_eq("encoding result", encodingResult, moscowEncoded);

      result.test_success("No crash");
      }
   catch(const std::exception &ex)
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
         results.push_back(test_asn1_ucs2_parsing());
         results.push_back(test_asn1_ucs4_parsing());
         results.push_back(test_asn1_ascii_encoding());
         results.push_back(test_asn1_utf8_encoding());

         return results;
         }
   };

BOTAN_REGISTER_TEST("asn1", ASN1_Tests);

#endif

}

