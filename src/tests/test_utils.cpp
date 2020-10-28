/*
* (C) 2015,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#define BOTAN_NO_DEPRECATED_WARNINGS

#include "tests.h"
#include <functional>
#include <ctime>
#include <botan/loadstor.h>
#include <botan/calendar.h>
#include <botan/internal/rounding.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/bit_ops.h>
#include <botan/cpuid.h>
#include <botan/charset.h>
#include <botan/parsing.h>
#include <botan/version.h>

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_BASE32_CODEC)
   #include <botan/base32.h>
#endif

#if defined(BOTAN_HAS_BASE58_CODEC)
   #include <botan/base58.h>
#endif

#if defined(BOTAN_HAS_POLY_DBL)
   #include <botan/internal/poly_dbl.h>
#endif

#if defined(BOTAN_HAS_UUID)
   #include <botan/uuid.h>
#endif

namespace Botan_Tests {

namespace {

class Utility_Function_Tests final : public Text_Based_Test
   {
   public:
      Utility_Function_Tests() : Text_Based_Test("util.vec", "In1,In2,Out") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         Test::Result result("Util " + algo);

         if(algo == "round_up")
            {
            const size_t x = vars.get_req_sz("In1");
            const size_t to = vars.get_req_sz("In2");

            result.test_eq(algo, Botan::round_up(x, to), vars.get_req_sz("Out"));

            try
               {
               Botan::round_up(x, 0);
               result.test_failure("round_up did not reject invalid input");
               }
            catch(std::exception&) {}
            }
         else if(algo == "round_down")
            {
            const size_t x = vars.get_req_sz("In1");
            const size_t to = vars.get_req_sz("In2");

            result.test_eq(algo, Botan::round_down<size_t>(x, to), vars.get_req_sz("Out"));
            result.test_eq(algo, Botan::round_down<size_t>(x, 0), x);
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_loadstore());

         return results;
         }

      Test::Result test_loadstore()
         {
         Test::Result result("Util load/store");

         const std::vector<uint8_t> membuf =
            Botan::hex_decode("00112233445566778899AABBCCDDEEFF");
         const uint8_t* mem = membuf.data();

         const uint16_t in16 = 0x1234;
         const uint32_t in32 = 0xA0B0C0D0;
         const uint64_t in64 = 0xABCDEF0123456789;

         result.test_is_eq<uint8_t>(Botan::get_byte(0, in32), 0xA0);
         result.test_is_eq<uint8_t>(Botan::get_byte(1, in32), 0xB0);
         result.test_is_eq<uint8_t>(Botan::get_byte(2, in32), 0xC0);
         result.test_is_eq<uint8_t>(Botan::get_byte(3, in32), 0xD0);

         result.test_is_eq<uint16_t>(Botan::make_uint16(0xAA, 0xBB), 0xAABB);
         result.test_is_eq<uint32_t>(Botan::make_uint32(0x01, 0x02, 0x03, 0x04), 0x01020304);

         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 0), 0x0011);
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 1), 0x2233);
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 2), 0x4455);
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 3), 0x6677);

         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 0), 0x1100);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 1), 0x3322);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 2), 0x5544);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 3), 0x7766);

         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 0), 0x00112233);
         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 1), 0x44556677);
         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 2), 0x8899AABB);
         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 3), 0xCCDDEEFF);

         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 0), 0x33221100);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 1), 0x77665544);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 2), 0xBBAA9988);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 3), 0xFFEEDDCC);

         result.test_is_eq<uint64_t>(Botan::load_be<uint64_t>(mem, 0), 0x0011223344556677);
         result.test_is_eq<uint64_t>(Botan::load_be<uint64_t>(mem, 1), 0x8899AABBCCDDEEFF);

         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem, 0), 0x7766554433221100);
         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem, 1), 0xFFEEDDCCBBAA9988);

         // Check misaligned loads:
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem + 1, 0), 0x1122);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem + 3, 0), 0x4433);

         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem + 1, 1), 0x55667788);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem + 3, 1), 0xAA998877);

         result.test_is_eq<uint64_t>(Botan::load_be<uint64_t>(mem + 1, 0), 0x1122334455667788);
         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem + 7, 0), 0xEEDDCCBBAA998877);
         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem + 5, 0), 0xCCBBAA9988776655);

         uint8_t outbuf[16] = { 0 };

         for(size_t offset = 0; offset != 7; ++offset)
            {
            uint8_t* out = outbuf + offset;

            Botan::store_be(in16, out);
            result.test_is_eq<uint8_t>(out[0], 0x12);
            result.test_is_eq<uint8_t>(out[1], 0x34);

            Botan::store_le(in16, out);
            result.test_is_eq<uint8_t>(out[0], 0x34);
            result.test_is_eq<uint8_t>(out[1], 0x12);

            Botan::store_be(in32, out);
            result.test_is_eq<uint8_t>(out[0], 0xA0);
            result.test_is_eq<uint8_t>(out[1], 0xB0);
            result.test_is_eq<uint8_t>(out[2], 0xC0);
            result.test_is_eq<uint8_t>(out[3], 0xD0);

            Botan::store_le(in32, out);
            result.test_is_eq<uint8_t>(out[0], 0xD0);
            result.test_is_eq<uint8_t>(out[1], 0xC0);
            result.test_is_eq<uint8_t>(out[2], 0xB0);
            result.test_is_eq<uint8_t>(out[3], 0xA0);

            Botan::store_be(in64, out);
            result.test_is_eq<uint8_t>(out[0], 0xAB);
            result.test_is_eq<uint8_t>(out[1], 0xCD);
            result.test_is_eq<uint8_t>(out[2], 0xEF);
            result.test_is_eq<uint8_t>(out[3], 0x01);
            result.test_is_eq<uint8_t>(out[4], 0x23);
            result.test_is_eq<uint8_t>(out[5], 0x45);
            result.test_is_eq<uint8_t>(out[6], 0x67);
            result.test_is_eq<uint8_t>(out[7], 0x89);

            Botan::store_le(in64, out);
            result.test_is_eq<uint8_t>(out[0], 0x89);
            result.test_is_eq<uint8_t>(out[1], 0x67);
            result.test_is_eq<uint8_t>(out[2], 0x45);
            result.test_is_eq<uint8_t>(out[3], 0x23);
            result.test_is_eq<uint8_t>(out[4], 0x01);
            result.test_is_eq<uint8_t>(out[5], 0xEF);
            result.test_is_eq<uint8_t>(out[6], 0xCD);
            result.test_is_eq<uint8_t>(out[7], 0xAB);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "util", Utility_Function_Tests);

class CT_Mask_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("CT utils");

         result.test_eq_sz("CT::is_zero8", Botan::CT::Mask<uint8_t>::is_zero(0).value(), 0xFF);
         result.test_eq_sz("CT::is_zero8", Botan::CT::Mask<uint8_t>::is_zero(1).value(), 0x00);
         result.test_eq_sz("CT::is_zero8", Botan::CT::Mask<uint8_t>::is_zero(0xFF).value(), 0x00);

         result.test_eq_sz("CT::is_zero16", Botan::CT::Mask<uint16_t>::is_zero(0).value(), 0xFFFF);
         result.test_eq_sz("CT::is_zero16", Botan::CT::Mask<uint16_t>::is_zero(1).value(), 0x0000);
         result.test_eq_sz("CT::is_zero16", Botan::CT::Mask<uint16_t>::is_zero(0xFF).value(), 0x0000);

         result.test_eq_sz("CT::is_zero32", Botan::CT::Mask<uint32_t>::is_zero(0).value(), 0xFFFFFFFF);
         result.test_eq_sz("CT::is_zero32", Botan::CT::Mask<uint32_t>::is_zero(1).value(), 0x00000000);
         result.test_eq_sz("CT::is_zero32", Botan::CT::Mask<uint32_t>::is_zero(0xFF).value(), 0x00000000);

         result.test_eq_sz("CT::is_less8", Botan::CT::Mask<uint8_t>::is_lt(0, 1).value(), 0xFF);
         result.test_eq_sz("CT::is_less8", Botan::CT::Mask<uint8_t>::is_lt(1, 0).value(), 0x00);
         result.test_eq_sz("CT::is_less8", Botan::CT::Mask<uint8_t>::is_lt(0xFF, 5).value(), 0x00);

         result.test_eq_sz("CT::is_less16", Botan::CT::Mask<uint16_t>::is_lt(0, 1).value(), 0xFFFF);
         result.test_eq_sz("CT::is_less16", Botan::CT::Mask<uint16_t>::is_lt(1, 0).value(), 0x0000);
         result.test_eq_sz("CT::is_less16", Botan::CT::Mask<uint16_t>::is_lt(0xFFFF, 5).value(), 0x0000);

         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(0, 1).value(), 0xFFFFFFFF);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(1, 0).value(), 0x00000000);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(0xFFFF5, 5).value(), 0x00000000);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(0xFFFFFFFF, 5).value(), 0x00000000);
         result.test_eq_sz("CT::is_less32", Botan::CT::Mask<uint32_t>::is_lt(5, 0xFFFFFFFF).value(), 0xFFFFFFFF);

         return {result};
         }
   };

BOTAN_REGISTER_TEST("utils", "ct_utils", CT_Mask_Tests);

class BitOps_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_power_of_2());
         results.push_back(test_ctz());
         results.push_back(test_sig_bytes());

         return results;
         }
   private:
      template<typename T>
      void test_ctz(Test::Result& result, T val, size_t expected)
         {
         result.test_eq("ctz(" + std::to_string(val) + ")", Botan::ctz<T>(val), expected);
         }

      Test::Result test_ctz()
         {
         Test::Result result("ctz");
         test_ctz<uint32_t>(result, 0, 32);
         test_ctz<uint32_t>(result, 1, 0);
         test_ctz<uint32_t>(result, 0x80, 7);
         test_ctz<uint32_t>(result, 0x8000000, 27);
         test_ctz<uint32_t>(result, 0x8100000, 20);
         test_ctz<uint32_t>(result, 0x80000000, 31);

         return result;
         }

      template<typename T>
      void test_sig_bytes(Test::Result& result, T val, size_t expected)
         {
         result.test_eq("significant_bytes(" + std::to_string(val) + ")",
                        Botan::significant_bytes<T>(val), expected);
         }

      Test::Result test_sig_bytes()
         {
         Test::Result result("significant_bytes");
         test_sig_bytes<uint32_t>(result, 0, 0);
         test_sig_bytes<uint32_t>(result, 1, 1);
         test_sig_bytes<uint32_t>(result, 0x80, 1);
         test_sig_bytes<uint32_t>(result, 255, 1);
         test_sig_bytes<uint32_t>(result, 256, 2);
         test_sig_bytes<uint32_t>(result, 65535, 2);
         test_sig_bytes<uint32_t>(result, 65536, 3);
         test_sig_bytes<uint32_t>(result, 0x80000000, 4);

         test_sig_bytes<uint64_t>(result, 0, 0);
         test_sig_bytes<uint64_t>(result, 1, 1);
         test_sig_bytes<uint64_t>(result, 0x80, 1);
         test_sig_bytes<uint64_t>(result, 256, 2);
         test_sig_bytes<uint64_t>(result, 0x80000000, 4);
         test_sig_bytes<uint64_t>(result, 0x100000000, 5);

         return result;
         }

      template<typename T>
      void test_power_of_2(Test::Result& result, T val, bool expected)
         {
         result.test_eq("power_of_2(" + std::to_string(val) + ")", Botan::is_power_of_2<T>(val), expected);
         }

      Test::Result test_power_of_2()
         {
         Test::Result result("is_power_of_2");

         test_power_of_2<uint32_t>(result, 0, false);
         test_power_of_2<uint32_t>(result, 1, false);
         test_power_of_2<uint32_t>(result, 2, true);
         test_power_of_2<uint32_t>(result, 3, false);
         test_power_of_2<uint32_t>(result, 0x8000, true);
         test_power_of_2<uint32_t>(result, 0x8001, false);
         test_power_of_2<uint32_t>(result, 0x8000000, true);

         test_power_of_2<uint64_t>(result, 0, false);
         test_power_of_2<uint64_t>(result, 1, false);
         test_power_of_2<uint64_t>(result, 2, true);
         test_power_of_2<uint64_t>(result, 3, false);
         test_power_of_2<uint64_t>(result, 0x8000, true);
         test_power_of_2<uint64_t>(result, 0x8001, false);
         test_power_of_2<uint64_t>(result, 0x8000000, true);
         test_power_of_2<uint64_t>(result, 0x100000000000, true);

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "bit_ops", BitOps_Tests);

#if defined(BOTAN_HAS_POLY_DBL)

class Poly_Double_Tests final : public Text_Based_Test
   {
   public:
      Poly_Double_Tests() : Text_Based_Test("poly_dbl.vec", "In,Out") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("Polynomial doubling");
         const std::vector<uint8_t> in  = vars.get_req_bin("In");
         const std::vector<uint8_t> out = vars.get_req_bin("Out");

         std::vector<uint8_t> b = in;
         Botan::poly_double_n(b.data(), b.size());

         result.test_eq("Expected value", b, out);
         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "poly_dbl", Poly_Double_Tests);

#endif

class Version_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("Versions");

         result.confirm("Version datestamp matches macro",
                        Botan::version_datestamp() == BOTAN_VERSION_DATESTAMP);

         const char* version_cstr = Botan::version_cstr();
         std::string version_str = Botan::version_string();
         result.test_eq("Same version string", version_str, std::string(version_cstr));

         const char* sversion_cstr = Botan::short_version_cstr();
         std::string sversion_str = Botan::short_version_string();
         result.test_eq("Same short version string", sversion_str, std::string(sversion_cstr));

         std::string expected_sversion =
            std::to_string(BOTAN_VERSION_MAJOR) + "." +
            std::to_string(BOTAN_VERSION_MINOR) + "." +
            std::to_string(BOTAN_VERSION_PATCH);

#if defined(BOTAN_VERSION_SUFFIX)
         expected_sversion += BOTAN_VERSION_SUFFIX_STR;
#endif

         result.test_eq("Short version string has expected format",
                        sversion_str, expected_sversion);

         const std::string version_check_ok =
            Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

         result.confirm("Correct version no warning", version_check_ok.empty());

         const std::string version_check_bad =
            Botan::runtime_version_check(1, 19, 42);

         const std::string expected_error =
            "Warning: linked version (" + sversion_str + ") does not match version built against (1.19.42)\n";

         result.test_eq("Expected warning text", version_check_bad, expected_error);

         return {result};
         }
   };

BOTAN_REGISTER_TEST("utils", "versioning", Version_Tests);

class Date_Format_Tests final : public Text_Based_Test
   {
   public:
      Date_Format_Tests() : Text_Based_Test("dates.vec", "Date") {}

      std::vector<uint32_t> parse_date(const std::string& s)
         {
         const std::vector<std::string> parts = Botan::split_on(s, ',');
         if(parts.size() != 6)
            {
            throw Test_Error("Bad date format '" + s + "'");
            }

         std::vector<uint32_t> u32s;
         for(auto const& sub : parts)
            {
            u32s.push_back(Botan::to_u32bit(sub));
            }
         return u32s;
         }

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         const std::string date_str = vars.get_req_str("Date");
         Test::Result result("Date parsing");

         const std::vector<uint32_t> d = parse_date(date_str);

         if(type == "valid" || type == "valid.not_std" || type == "valid.64_bit_time_t")
            {
            Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]);
            result.test_is_eq(date_str + " year", c.get_year(), d[0]);
            result.test_is_eq(date_str + " month", c.get_month(), d[1]);
            result.test_is_eq(date_str + " day", c.get_day(), d[2]);
            result.test_is_eq(date_str + " hour", c.get_hour(), d[3]);
            result.test_is_eq(date_str + " minute", c.get_minutes(), d[4]);
            result.test_is_eq(date_str + " second", c.get_seconds(), d[5]);

            if(type == "valid.not_std" || (type == "valid.64_bit_time_t" && c.get_year() > 2037 && sizeof(std::time_t) == 4))
               {
               result.test_throws("valid but out of std::timepoint range", [c]() { c.to_std_timepoint(); });
               }
            else
               {
               Botan::calendar_point c2 = Botan::calendar_value(c.to_std_timepoint());
               result.test_is_eq(date_str + " year", c2.get_year(), d[0]);
               result.test_is_eq(date_str + " month", c2.get_month(), d[1]);
               result.test_is_eq(date_str + " day", c2.get_day(), d[2]);
               result.test_is_eq(date_str + " hour", c2.get_hour(), d[3]);
               result.test_is_eq(date_str + " minute", c2.get_minutes(), d[4]);
               result.test_is_eq(date_str + " second", c2.get_seconds(), d[5]);
               }
            }
         else if(type == "invalid")
            {
            result.test_throws("invalid date", [d]() { Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]); });
            }
         else
            {
            throw Test_Error("Unexpected header '" + type + "' in date format tests");
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("calendar_point::to_string");
         Botan::calendar_point d(2008, 5, 15, 9, 30, 33);
         // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
         result.test_eq("calendar_point::to_string", d.to_string(), "2008-05-15T09:30:33");
         return {result};
         }
   };

BOTAN_REGISTER_TEST("utils", "util_dates", Date_Format_Tests);

#if defined(BOTAN_HAS_BASE32_CODEC)

class Base32_Tests final : public Text_Based_Test
   {
   public:
      Base32_Tests() : Text_Based_Test("base32.vec", "Base32", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Base32");

         const bool is_valid = (type == "valid");
         const std::string base32 = vars.get_req_str("Base32");

         try
            {
            if(is_valid)
               {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_eq("base32 decoding", Botan::base32_decode(base32), binary);
               result.test_eq("base32 encoding", Botan::base32_encode(binary), base32);
               }
            else
               {
               auto res = Botan::base32_decode(base32);
               result.test_failure("decoded invalid base32 to " + Botan::hex_encode(res));
               }
            }
         catch(std::exception& e)
            {
            if(is_valid)
               {
               result.test_failure("rejected valid base32", e.what());
               }
            else
               {
               result.test_note("rejected invalid base32");
               }
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("Base32");
         const std::string valid_b32 = "MY======";

         for(char ws_char : { ' ', '\t', '\r', '\n' })
            {
            for(size_t i = 0; i <= valid_b32.size(); ++i)
               {
               std::string b32_ws = valid_b32;
               b32_ws.insert(i, 1, ws_char);

               try
                  {
                  result.test_failure("decoded whitespace base32", Botan::base32_decode(b32_ws, false));
                  }
               catch(std::exception&) {}

               try
                  {
                  result.test_eq("base32 decoding with whitespace", Botan::base32_decode(b32_ws, true), "66");
                  }
               catch(std::exception& e)
                  {
                  result.test_failure(b32_ws, e.what());
                  }
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("utils", "base32", Base32_Tests);

#endif

#if defined(BOTAN_HAS_BASE58_CODEC)

class Base58_Tests final : public Text_Based_Test
   {
   public:
      Base58_Tests() : Text_Based_Test("base58.vec", "Base58", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Base58");

         const bool is_valid = (type == "valid");
         const std::string base58 = vars.get_req_str("Base58");

         try
            {
            if(is_valid)
               {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_eq("base58 decoding", Botan::base58_decode(base58), binary);
               result.test_eq("base58 encoding", Botan::base58_encode(binary), base58);
               }
            else
               {
               auto res = Botan::base58_decode(base58);
               result.test_failure("decoded invalid base58 to " + Botan::hex_encode(res));
               }
            }
         catch(std::exception& e)
            {
            if(is_valid)
               {
               result.test_failure("rejected valid base58", e.what());
               }
            else
               {
               result.test_note("rejected invalid base58");
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "base58", Base58_Tests);

class Base58_Check_Tests final : public Text_Based_Test
   {
   public:
      Base58_Check_Tests() : Text_Based_Test("base58c.vec", "Base58", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Base58 Check");

         const bool is_valid = (type == "valid");
         const std::string base58 = vars.get_req_str("Base58");

         try
            {
            if(is_valid)
               {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_eq("base58 decoding", Botan::base58_check_decode(base58), binary);
               result.test_eq("base58 encoding", Botan::base58_check_encode(binary), base58);
               }
            else
               {
               auto res = Botan::base58_check_decode(base58);
               result.test_failure("decoded invalid base58c to " + Botan::hex_encode(res));
               }
            }
         catch(std::exception& e)
            {
            if(is_valid)
               {
               result.test_failure("rejected valid base58c", e.what());
               }
            else
               {
               result.test_note("rejected invalid base58c");
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "base58c", Base58_Check_Tests);

#endif

#if defined(BOTAN_HAS_BASE64_CODEC)

class Base64_Tests final : public Text_Based_Test
   {
   public:
      Base64_Tests() : Text_Based_Test("base64.vec", "Base64", "Binary") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Base64");

         const bool is_valid = (type == "valid");
         const std::string base64 = vars.get_req_str("Base64");

         try
            {
            if(is_valid)
               {
               const std::vector<uint8_t> binary = vars.get_req_bin("Binary");
               result.test_eq("base64 decoding", Botan::base64_decode(base64), binary);
               result.test_eq("base64 encoding", Botan::base64_encode(binary), base64);
               }
            else
               {
               auto res = Botan::base64_decode(base64);
               result.test_failure("decoded invalid base64 to " + Botan::hex_encode(res));
               }
            }
         catch(std::exception& e)
            {
            if(is_valid)
               {
               result.test_failure("rejected valid base64", e.what());
               }
            else
               {
               result.test_note("rejected invalid base64");
               }
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("Base64");
         const std::string valid_b64 = "Zg==";

         for(char ws_char : { ' ', '\t', '\r', '\n' })
            {
            for(size_t i = 0; i <= valid_b64.size(); ++i)
               {
               std::string b64_ws = valid_b64;
               b64_ws.insert(i, 1, ws_char);

               try
                  {
                  result.test_failure("decoded whitespace base64", Botan::base64_decode(b64_ws, false));
                  }
               catch(std::exception&) {}

               try
                  {
                  result.test_eq("base64 decoding with whitespace", Botan::base64_decode(b64_ws, true), "66");
                  }
               catch(std::exception& e)
                  {
                  result.test_failure(b64_ws, e.what());
                  }
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("utils", "base64", Base64_Tests);

#endif

class Charset_Tests final : public Text_Based_Test
   {
   public:
      Charset_Tests() : Text_Based_Test("charset.vec", "In,Out") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Charset");

         const std::vector<uint8_t> in = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         const std::string in_str(in.begin(), in.end());

         std::string converted;

         if(type == "UCS2-UTF8")
            {
            converted = Botan::ucs2_to_utf8(in.data(), in.size());
            }
         else if(type == "UCS4-UTF8")
            {
            converted = Botan::ucs4_to_utf8(in.data(), in.size());
            }
         else if(type == "UTF8-LATIN1")
            {
            converted = Botan::utf8_to_latin1(in_str);
            }
         else if(type == "UTF16-LATIN1")
            {
            converted = Botan::Charset::transcode(in_str,
                                                  Botan::Character_Set::LATIN1_CHARSET,
                                                  Botan::Character_Set::UCS2_CHARSET);
            }
         else if(type == "LATIN1-UTF8")
            {
            converted = Botan::Charset::transcode(in_str,
                                                  Botan::Character_Set::UTF8_CHARSET,
                                                  Botan::Character_Set::LATIN1_CHARSET);
            }
         else
            {
            throw Test_Error("Unexpected header '" + type + "' in charset tests");
            }

         result.test_eq("string converted successfully", std::vector<uint8_t>(converted.begin(), converted.end()), expected);

         return result;
         }

      Test::Result utf16_to_latin1_negative_tests()
         {
         Test::Result result("Charset negative tests");

         result.test_throws("conversion fails for non-Latin1 characters", []()
            {
            // "abcdefŸabcdef"
            std::vector<uint8_t> input = { 0x00, 0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x64, 0x00, 0x65, 0x00, 0x66, 0x01,
                                           0x78, 0x00, 0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x64, 0x00, 0x65, 0x00, 0x66
                                         };

            Botan::Charset::transcode(std::string(input.begin(), input.end()),
                                      Botan::Character_Set::LATIN1_CHARSET,
                                      Botan::Character_Set::UCS2_CHARSET);
            });

         result.test_throws("conversion fails for UTF16 string with odd number of bytes", []()
            {
            std::vector<uint8_t> input = { 0x00, 0x61, 0x00 };

            Botan::Charset::transcode(std::string(input.begin(), input.end()),
                                      Botan::Character_Set::LATIN1_CHARSET,
                                      Botan::Character_Set::UCS2_CHARSET);
            });

         return result;
         }

      Test::Result utf8_to_latin1_negative_tests()
         {
         Test::Result result("Charset negative tests");

         result.test_throws("conversion fails for non-Latin1 characters", []()
            {
            // "abcdefŸabcdef"
            const std::vector<uint8_t> input =
               {
               0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xC5,
               0xB8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
               };

            Botan::utf8_to_latin1(std::string(input.begin(), input.end()));
            });

         result.test_throws("invalid utf-8 string", []()
            {
            // sequence truncated
            const std::vector<uint8_t> input = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xC5 };
            Botan::utf8_to_latin1(std::string(input.begin(), input.end()));
            });

         result.test_throws("invalid utf-8 string", []()
            {
            std::vector<uint8_t> input = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xC8, 0xB8, 0x61 };
            Botan::utf8_to_latin1(std::string(input.begin(), input.end()));
            });

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("Charset negative tests");

         result.merge(utf16_to_latin1_negative_tests());
         result.merge(utf8_to_latin1_negative_tests());

         return{ result };
         }

   };

BOTAN_REGISTER_TEST("utils", "charset", Charset_Tests);

class Hostname_Tests final : public Text_Based_Test
   {
   public:
      Hostname_Tests() : Text_Based_Test("hostnames.vec", "Issued,Hostname")
         {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Hostname Matching");

         const std::string issued = vars.get_req_str("Issued");
         const std::string hostname = vars.get_req_str("Hostname");
         const bool expected = (type == "Invalid") ? false : true;

         const std::string what = hostname + ((expected == true) ?
                                              " matches " : " does not match ") + issued;
         result.test_eq(what, Botan::host_wildcard_match(issued, hostname), expected);

         return result;
         }
   };

BOTAN_REGISTER_TEST("utils", "hostname", Hostname_Tests);

class ReadKV_Tests final : public Text_Based_Test
   {
   public:
      ReadKV_Tests() : Text_Based_Test("utils/read_kv.vec", "Input,Expected") {}

      Test::Result run_one_test(const std::string& status, const VarMap& vars) override
         {
         Test::Result result("read_kv");

         const bool is_valid = (status == "Valid");

         const std::string input = vars.get_req_str("Input");
         const std::string expected = vars.get_req_str("Expected");

         if(is_valid)
            {
            confirm_kv(result, Botan::read_kv(input), split_group(expected));
            }
         else
            {
            // In this case "expected" is the expected exception message
            result.test_throws("Invalid key value input throws exception",
                               expected,
                               [&]() { Botan::read_kv(input); });
            }
         return result;
         }

   private:

      std::vector<std::string> split_group(const std::string& str)
         {
         std::vector<std::string> elems;
         if(str.empty()) return elems;

         std::string substr;
         for(auto i = str.begin(); i != str.end(); ++i)
            {
            if(*i == '|')
               {
               elems.push_back(substr);
               substr.clear();
               }
            else
               {
               substr += *i;
               }
            }

         if(!substr.empty())
            elems.push_back(substr);

         return elems;
         }

      void confirm_kv(Test::Result& result,
                      const std::map<std::string, std::string>& kv,
                      const std::vector<std::string>& expected)
         {
         if(!result.test_eq("expected size", expected.size() % 2, size_t(0)))
            return;

         for(size_t i = 0; i != expected.size(); i += 2)
            {
            auto j = kv.find(expected[i]);
            if(result.confirm("Found key", j != kv.end()))
               {
               result.test_eq("Matching value", j->second, expected[i+1]);
               }
            }

         result.test_eq("KV has same size as expected", kv.size(), expected.size()/2);
         }
   };

BOTAN_REGISTER_TEST("utils", "util_read_kv", ReadKV_Tests);

class CPUID_Tests final : public Test
   {
   public:

      std::vector<Test::Result> run() override
         {
         Test::Result result("CPUID");

         result.confirm("Endian is either little or big",
                        Botan::CPUID::is_big_endian() || Botan::CPUID::is_little_endian());

         if(Botan::CPUID::is_little_endian())
            {
            result.test_eq("If endian is little, it is not also big endian", Botan::CPUID::is_big_endian(), false);
            }
         else
            {
            result.test_eq("If endian is big, it is not also little endian", Botan::CPUID::is_little_endian(), false);
            }

         const size_t cache_line_size = Botan::CPUID::cache_line_size();

         result.test_gte("Cache line size is >= 16", cache_line_size, 16);
         result.test_lte("Cache line size is <= 256", cache_line_size, 256);
         result.confirm("Cache line size is a power of 2", Botan::is_power_of_2(cache_line_size));

         const std::string cpuid_string = Botan::CPUID::to_string();
         result.test_success("CPUID::to_string doesn't crash");

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

         if(Botan::CPUID::has_sse2())
            {
            result.confirm("Output string includes sse2", cpuid_string.find("sse2") != std::string::npos);

            Botan::CPUID::clear_cpuid_bit(Botan::CPUID::CPUID_SSE2_BIT);

            result.test_eq("After clearing cpuid bit, has_sse2 returns false", Botan::CPUID::has_sse2(), false);

            Botan::CPUID::initialize(); // reset state
            result.test_eq("After reinitializing, has_sse2 returns true", Botan::CPUID::has_sse2(), true);
            }
#endif

         return {result};
         }
   };

BOTAN_REGISTER_TEST("utils", "cpuid", CPUID_Tests);

#if defined(BOTAN_HAS_UUID)

class UUID_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("UUID");

         const Botan::UUID empty_uuid;
         const Botan::UUID random_uuid1(Test::rng());
         const Botan::UUID random_uuid2(Test::rng());
         const Botan::UUID loaded_uuid(std::vector<uint8_t>(16, 4));

         result.test_throws("Cannot load wrong number of bytes", []() { Botan::UUID u(std::vector<uint8_t>(15)); });

         result.test_eq("Empty UUID is empty", empty_uuid.is_valid(), false);
         result.confirm("Empty UUID equals another empty UUID", empty_uuid == Botan::UUID());

         result.test_throws("Empty UUID cannot become a string", [&]() { empty_uuid.to_string(); });

         result.test_eq("Random UUID not empty", random_uuid1.is_valid(), true);
         result.test_eq("Random UUID not empty", random_uuid2.is_valid(), true);

         result.confirm("Random UUIDs are distinct", random_uuid1 != random_uuid2);
         result.confirm("Random UUIDs not equal to empty", random_uuid1 != empty_uuid);

         const std::string uuid4_str = loaded_uuid.to_string();
         result.test_eq("String matches expected", uuid4_str, "04040404-0404-0404-0404-040404040404");

         const std::string uuid_r1_str = random_uuid1.to_string();
         result.confirm("UUID from string matches", Botan::UUID(uuid_r1_str) == random_uuid1);

         class AllSame_RNG : public Botan::RandomNumberGenerator
            {
            public:
               AllSame_RNG(uint8_t b) : m_val(b) {}

               void randomize(uint8_t out[], size_t len) override
                  {
                  for(size_t i = 0; i != len; ++i)
                     out[i] = m_val;
                  }

               std::string name() const override { return "zeros"; }
               bool accepts_input() const override { return false; }
               void add_entropy(const uint8_t[], size_t) override {}
               void clear() override {}
               bool is_seeded() const override { return true; }
            private:
               uint8_t m_val;
            };

         AllSame_RNG zeros(0x00);
         const Botan::UUID zero_uuid(zeros);
         result.test_eq("Zero UUID matches expected", zero_uuid.to_string(), "00000000-0000-4000-8000-000000000000");

         AllSame_RNG ones(0xFF);
         const Botan::UUID ones_uuid(ones);
         result.test_eq("Ones UUID matches expected", ones_uuid.to_string(), "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF");

         return {result};
         }

   };

BOTAN_REGISTER_TEST("utils", "uuid", UUID_Tests);

#endif

}

}
