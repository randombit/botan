/*
* (C) 2015,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/version.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/calendar.h>
#include <botan/internal/charset.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <botan/internal/rounding.h>
#include <ctime>
#include <functional>

#if defined(BOTAN_HAS_POLY_DBL)
   #include <botan/internal/poly_dbl.h>
#endif

#if defined(BOTAN_HAS_UUID)
   #include <botan/uuid.h>
#endif

namespace Botan_Tests {

namespace {

class Utility_Function_Tests final : public Text_Based_Test {
   public:
      Utility_Function_Tests() : Text_Based_Test("util.vec", "In1,In2,Out") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         Test::Result result("Util " + algo);

         if(algo == "round_up") {
            const size_t x = vars.get_req_sz("In1");
            const size_t to = vars.get_req_sz("In2");

            result.test_eq(algo, Botan::round_up(x, to), vars.get_req_sz("Out"));

            try {
               Botan::round_up(x, 0);
               result.test_failure("round_up did not reject invalid input");
            } catch(std::exception&) {}
         } else if(algo == "round_down") {
            const size_t x = vars.get_req_sz("In1");
            const size_t to = vars.get_req_sz("In2");

            result.test_eq(algo, Botan::round_down<size_t>(x, to), vars.get_req_sz("Out"));
            result.test_eq(algo, Botan::round_down<size_t>(x, 0), x);
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         std::vector<Test::Result> results;

         results.push_back(test_loadstore());

         return results;
      }

      static Test::Result test_loadstore() {
         Test::Result result("Util load/store");

         const std::vector<uint8_t> membuf = Botan::hex_decode("00112233445566778899AABBCCDDEEFF");
         const uint8_t* mem = membuf.data();

         const uint16_t in16 = 0x1234;
         const uint32_t in32 = 0xA0B0C0D0;
         const uint64_t in64 = 0xABCDEF0123456789;

         result.test_is_eq<uint8_t>(Botan::get_byte<0>(in32), 0xA0);
         result.test_is_eq<uint8_t>(Botan::get_byte<1>(in32), 0xB0);
         result.test_is_eq<uint8_t>(Botan::get_byte<2>(in32), 0xC0);
         result.test_is_eq<uint8_t>(Botan::get_byte<3>(in32), 0xD0);

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

         uint8_t outbuf[16] = {0};

         for(size_t offset = 0; offset != 7; ++offset) {
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

         std::array<uint8_t, 8> outarr;
         uint16_t i0, i1, i2, i3;
         Botan::store_be(in64, outarr);

         Botan::load_be(outarr, i0, i1, i2, i3);
         result.test_is_eq<uint16_t>(i0, 0xABCD);
         result.test_is_eq<uint16_t>(i1, 0xEF01);
         result.test_is_eq<uint16_t>(i2, 0x2345);
         result.test_is_eq<uint16_t>(i3, 0x6789);

         Botan::load_le(std::span{outarr}.first<6>(), i0, i1, i2);
         result.test_is_eq<uint16_t>(i0, 0xCDAB);
         result.test_is_eq<uint16_t>(i1, 0x01EF);
         result.test_is_eq<uint16_t>(i2, 0x4523);
         result.test_is_eq<uint16_t>(i3, 0x6789);  // remains unchanged

         Botan::store_le(in64, outarr);

         Botan::load_le(outarr, i0, i1, i2, i3);
         result.test_is_eq<uint16_t>(i0, 0x6789);
         result.test_is_eq<uint16_t>(i1, 0x2345);
         result.test_is_eq<uint16_t>(i2, 0xEF01);
         result.test_is_eq<uint16_t>(i3, 0xABCD);

         Botan::load_be(std::span{outarr}.first<6>(), i0, i1, i2);
         result.test_is_eq<uint16_t>(i0, 0x8967);
         result.test_is_eq<uint16_t>(i1, 0x4523);
         result.test_is_eq<uint16_t>(i2, 0x01EF);
         result.test_is_eq<uint16_t>(i3, 0xABCD);  // remains unchanged

         result.test_is_eq(in16, Botan::load_be(Botan::store_be(in16)));
         result.test_is_eq(in32, Botan::load_be(Botan::store_be(in32)));
         result.test_is_eq(in64, Botan::load_be(Botan::store_be(in64)));

         result.test_is_eq(in16, Botan::load_le(Botan::store_le(in16)));
         result.test_is_eq(in32, Botan::load_le(Botan::store_le(in32)));
         result.test_is_eq(in64, Botan::load_le(Botan::store_le(in64)));

         return result;
      }
};

BOTAN_REGISTER_SMOKE_TEST("utils", "util", Utility_Function_Tests);

class CT_Mask_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
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

         for(auto bad_input : {0, 1}) {
            for(size_t input_length : {0, 1, 2, 32}) {
               for(size_t offset = 0; offset != input_length + 1; ++offset) {
                  const auto mask = Botan::CT::Mask<uint8_t>::expand(static_cast<uint8_t>(bad_input));

                  std::vector<uint8_t> input(input_length);
                  this->rng().randomize(input.data(), input.size());

                  auto output = Botan::CT::copy_output(mask, input.data(), input.size(), offset);

                  result.test_eq_sz("CT::copy_output capacity", output.capacity(), input.size());

                  if(bad_input) {
                     result.confirm("If bad input, no output", output.empty());
                  } else {
                     if(offset >= input_length) {
                        result.confirm("If offset is too large, output is empty", output.empty());
                     } else {
                        result.test_eq_sz("CT::copy_output length", output.size(), input.size() - offset);

                        for(size_t i = 0; i != output.size(); ++i) {
                           result.test_eq_sz("CT::copy_output offset", output[i], input[i + offset]);
                        }
                     }
                  }
               }
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "ct_utils", CT_Mask_Tests);

class BitOps_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_power_of_2());
         results.push_back(test_ctz());
         results.push_back(test_sig_bytes());

         return results;
      }

   private:
      template <typename T>
      void test_ctz(Test::Result& result, T val, size_t expected) {
         result.test_eq("ctz(" + std::to_string(val) + ")", Botan::ctz<T>(val), expected);
      }

      Test::Result test_ctz() {
         Test::Result result("ctz");
         test_ctz<uint32_t>(result, 0, 32);
         test_ctz<uint32_t>(result, 1, 0);
         test_ctz<uint32_t>(result, 0x80, 7);
         test_ctz<uint32_t>(result, 0x8000000, 27);
         test_ctz<uint32_t>(result, 0x8100000, 20);
         test_ctz<uint32_t>(result, 0x80000000, 31);

         return result;
      }

      template <typename T>
      void test_sig_bytes(Test::Result& result, T val, size_t expected) {
         result.test_eq("significant_bytes(" + std::to_string(val) + ")", Botan::significant_bytes<T>(val), expected);
      }

      Test::Result test_sig_bytes() {
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

      template <typename T>
      void test_power_of_2(Test::Result& result, T val, bool expected) {
         result.test_eq("power_of_2(" + std::to_string(val) + ")", Botan::is_power_of_2<T>(val), expected);
      }

      Test::Result test_power_of_2() {
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

class Poly_Double_Tests final : public Text_Based_Test {
   public:
      Poly_Double_Tests() : Text_Based_Test("poly_dbl.vec", "In,Out") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("Polynomial doubling");
         const std::vector<uint8_t> in = vars.get_req_bin("In");
         const std::vector<uint8_t> out = vars.get_req_bin("Out");

         std::vector<uint8_t> b = in;
         Botan::poly_double_n(b.data(), b.size());

         result.test_eq("Expected value", b, out);
         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "poly_dbl", Poly_Double_Tests);

#endif

class Version_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Versions");

         result.confirm("Version datestamp matches macro", Botan::version_datestamp() == BOTAN_VERSION_DATESTAMP);

         const char* version_cstr = Botan::version_cstr();
         std::string version_str = Botan::version_string();
         result.test_eq("Same version string", version_str, std::string(version_cstr));

         const char* sversion_cstr = Botan::short_version_cstr();
         std::string sversion_str = Botan::short_version_string();
         result.test_eq("Same short version string", sversion_str, std::string(sversion_cstr));

         std::string expected_sversion = std::to_string(BOTAN_VERSION_MAJOR) + "." +
                                         std::to_string(BOTAN_VERSION_MINOR) + "." +
                                         std::to_string(BOTAN_VERSION_PATCH);

#if defined(BOTAN_VERSION_SUFFIX)
         expected_sversion += BOTAN_VERSION_SUFFIX_STR;
#endif

         result.test_eq("Short version string has expected format", sversion_str, expected_sversion);

         const std::string version_check_ok =
            Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

         result.confirm("Correct version no warning", version_check_ok.empty());

         const std::string version_check_bad = Botan::runtime_version_check(1, 19, 42);

         const std::string expected_error =
            "Warning: linked version (" + sversion_str + ") does not match version built against (1.19.42)\n";

         result.test_eq("Expected warning text", version_check_bad, expected_error);

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "versioning", Version_Tests);

class Date_Format_Tests final : public Text_Based_Test {
   public:
      Date_Format_Tests() : Text_Based_Test("dates.vec", "Date") {}

      static std::vector<uint32_t> parse_date(const std::string& s) {
         const std::vector<std::string> parts = Botan::split_on(s, ',');
         if(parts.size() != 6) {
            throw Test_Error("Bad date format '" + s + "'");
         }

         std::vector<uint32_t> u32s;
         u32s.reserve(parts.size());
         for(const auto& sub : parts) {
            u32s.push_back(Botan::to_u32bit(sub));
         }
         return u32s;
      }

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         const std::string date_str = vars.get_req_str("Date");
         Test::Result result("Date parsing");

         const std::vector<uint32_t> d = parse_date(date_str);

         if(type == "valid" || type == "valid.not_std" || type == "valid.64_bit_time_t") {
            Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]);
            result.test_is_eq(date_str + " year", c.year(), d[0]);
            result.test_is_eq(date_str + " month", c.month(), d[1]);
            result.test_is_eq(date_str + " day", c.day(), d[2]);
            result.test_is_eq(date_str + " hour", c.hour(), d[3]);
            result.test_is_eq(date_str + " minute", c.minutes(), d[4]);
            result.test_is_eq(date_str + " second", c.seconds(), d[5]);

            if(type == "valid.not_std" ||
               (type == "valid.64_bit_time_t" && c.year() > 2037 && sizeof(std::time_t) == 4)) {
               result.test_throws("valid but out of std::timepoint range", [c]() { c.to_std_timepoint(); });
            } else {
               Botan::calendar_point c2(c.to_std_timepoint());
               result.test_is_eq(date_str + " year", c2.year(), d[0]);
               result.test_is_eq(date_str + " month", c2.month(), d[1]);
               result.test_is_eq(date_str + " day", c2.day(), d[2]);
               result.test_is_eq(date_str + " hour", c2.hour(), d[3]);
               result.test_is_eq(date_str + " minute", c2.minutes(), d[4]);
               result.test_is_eq(date_str + " second", c2.seconds(), d[5]);
            }
         } else if(type == "invalid") {
            result.test_throws("invalid date", [d]() { Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]); });
         } else {
            throw Test_Error("Unexpected header '" + type + "' in date format tests");
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("calendar_point::to_string");
         Botan::calendar_point d(2008, 5, 15, 9, 30, 33);
         // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
         result.test_eq("calendar_point::to_string", d.to_string(), "2008-05-15T09:30:33");
         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "util_dates", Date_Format_Tests);

class Charset_Tests final : public Text_Based_Test {
   public:
      Charset_Tests() : Text_Based_Test("charset.vec", "In,Out") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Charset");

         const std::vector<uint8_t> in = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         const std::string in_str(in.begin(), in.end());

         std::string converted;

         if(type == "UCS2-UTF8") {
            converted = Botan::ucs2_to_utf8(in.data(), in.size());
         } else if(type == "UCS4-UTF8") {
            converted = Botan::ucs4_to_utf8(in.data(), in.size());
         } else if(type == "LATIN1-UTF8") {
            converted = Botan::latin1_to_utf8(in.data(), in.size());
         } else {
            throw Test_Error("Unexpected header '" + type + "' in charset tests");
         }

         result.test_eq(
            "string converted successfully", std::vector<uint8_t>(converted.begin(), converted.end()), expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "charset", Charset_Tests);

class Hostname_Tests final : public Text_Based_Test {
   public:
      Hostname_Tests() : Text_Based_Test("hostnames.vec", "Issued,Hostname") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Hostname Matching");

         const std::string issued = vars.get_req_str("Issued");
         const std::string hostname = vars.get_req_str("Hostname");
         const bool expected = (type == "Invalid") ? false : true;

         const std::string what = hostname + ((expected == true) ? " matches " : " does not match ") + issued;
         result.test_eq(what, Botan::host_wildcard_match(issued, hostname), expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "hostname", Hostname_Tests);

class ReadKV_Tests final : public Text_Based_Test {
   public:
      ReadKV_Tests() : Text_Based_Test("utils/read_kv.vec", "Input,Expected") {}

      Test::Result run_one_test(const std::string& status, const VarMap& vars) override {
         Test::Result result("read_kv");

         const bool is_valid = (status == "Valid");

         const std::string input = vars.get_req_str("Input");
         const std::string expected = vars.get_req_str("Expected");

         if(is_valid) {
            confirm_kv(result, Botan::read_kv(input), split_group(expected));
         } else {
            // In this case "expected" is the expected exception message
            result.test_throws("Invalid key value input throws exception", expected, [&]() { Botan::read_kv(input); });
         }
         return result;
      }

   private:
      static std::vector<std::string> split_group(const std::string& str) {
         std::vector<std::string> elems;
         if(str.empty()) {
            return elems;
         }

         std::string substr;
         for(auto i = str.begin(); i != str.end(); ++i) {
            if(*i == '|') {
               elems.push_back(substr);
               substr.clear();
            } else {
               substr += *i;
            }
         }

         if(!substr.empty()) {
            elems.push_back(substr);
         }

         return elems;
      }

      static void confirm_kv(Test::Result& result,
                             const std::map<std::string, std::string>& kv,
                             const std::vector<std::string>& expected) {
         if(!result.test_eq("expected size", expected.size() % 2, size_t(0))) {
            return;
         }

         for(size_t i = 0; i != expected.size(); i += 2) {
            auto j = kv.find(expected[i]);
            if(result.confirm("Found key", j != kv.end())) {
               result.test_eq("Matching value", j->second, expected[i + 1]);
            }
         }

         result.test_eq("KV has same size as expected", kv.size(), expected.size() / 2);
      }
};

BOTAN_REGISTER_TEST("utils", "util_read_kv", ReadKV_Tests);

class CPUID_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("CPUID");

         result.confirm("Endian is either little or big",
                        Botan::CPUID::is_big_endian() || Botan::CPUID::is_little_endian());

         if(Botan::CPUID::is_little_endian()) {
            result.test_eq("If endian is little, it is not also big endian", Botan::CPUID::is_big_endian(), false);
         } else {
            result.test_eq("If endian is big, it is not also little endian", Botan::CPUID::is_little_endian(), false);
         }

         const std::string cpuid_string = Botan::CPUID::to_string();
         result.test_success("CPUID::to_string doesn't crash");

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

         if(Botan::CPUID::has_sse2()) {
            result.confirm("Output string includes sse2", cpuid_string.find("sse2") != std::string::npos);

            Botan::CPUID::clear_cpuid_bit(Botan::CPUID::CPUID_SSE2_BIT);

            result.test_eq("After clearing cpuid bit, has_sse2 returns false", Botan::CPUID::has_sse2(), false);

            Botan::CPUID::initialize();  // reset state
            result.test_eq("After reinitializing, has_sse2 returns true", Botan::CPUID::has_sse2(), true);
         }
#endif

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "cpuid", CPUID_Tests);

#if defined(BOTAN_HAS_UUID)

class UUID_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("UUID");

         const Botan::UUID empty_uuid;
         const Botan::UUID random_uuid1(this->rng());
         const Botan::UUID random_uuid2(this->rng());
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

         class AllSame_RNG : public Botan::RandomNumberGenerator {
            public:
               explicit AllSame_RNG(uint8_t b) : m_val(b) {}

               void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
                  for(auto& byte : output) {
                     byte = m_val;
                  }
               }

               std::string name() const override { return "zeros"; }

               bool accepts_input() const override { return false; }

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

class Formatter_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Format utility");

         /*
         In a number of these tests, we are not strictly depending on the
         behavior, for instance checking `fmt("{}") == "{}"` is more about
         checking that we don't crash, rather than we return that precise string.
         */

         result.test_eq("test 1", Botan::fmt("hi"), "hi");
         result.test_eq("test 2", Botan::fmt("ignored", 5), "ignored");
         result.test_eq("test 3", Botan::fmt("answer is {}", 42), "answer is 42");
         result.test_eq("test 4", Botan::fmt("{", 5), "{");
         result.test_eq("test 4", Botan::fmt("{}"), "{}");
         result.test_eq("test 5", Botan::fmt("{} == '{}'", 5, "five"), "5 == 'five'");

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "fmt", Formatter_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
