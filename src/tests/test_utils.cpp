/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <functional>
#include <botan/loadstor.h>
#include <botan/calendar.h>
#include <botan/internal/rounding.h>

#if defined(BOTAN_HAS_BASE64_CODEC)
  #include <botan/base64.h>
#endif

namespace Botan_Tests {

namespace {

class Utility_Function_Tests : public Text_Based_Test
   {
   public:
      Utility_Function_Tests() : Text_Based_Test(Test::data_file("util.vec"),
                                                      {"In1","In2","Out"})
         {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         Test::Result result("Util " + algo);

         if(algo == "round_up")
            {
            const size_t x = get_req_sz(vars, "In1");
            const size_t to = get_req_sz(vars, "In2");

            result.test_eq(algo.c_str(), Botan::round_up(x, to), get_req_sz(vars, "Out"));

            try
               {
               Botan::round_up(x, 0);
               result.test_failure("round_up did not reject invalid input");
               }
            catch(std::exception) {}
            }
         else if(algo == "round_down")
            {
            const size_t x = get_req_sz(vars, "In1");
            const size_t to = get_req_sz(vars, "In2");

            result.test_eq(algo.c_str(), Botan::round_down<size_t>(x, to), get_req_sz(vars, "Out"));
            result.test_eq(algo.c_str(), Botan::round_down<size_t>(x, 0), x);
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         std::vector<Test::Result> results;


         return results;

         }
   };

BOTAN_REGISTER_TEST("util", Utility_Function_Tests);

class Date_Format_Tests : public Text_Based_Test
   {
   public:
      Date_Format_Tests() : Text_Based_Test(Test::data_file("dates.vec"),
                                            std::vector<std::string>{"Date"})
         {}

      std::vector<uint32_t> parse_date(const std::string& s)
         {
         const std::vector<std::string> parts = Botan::split_on(s, ',');
         if(parts.size() != 6)
            throw std::runtime_error("Bad date format '" + s + "'");

         std::vector<uint32_t> u32s;
         for(auto&& sub : parts)
            {
            u32s.push_back(Botan::to_u32bit(sub));
            }
         return u32s;
         }

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Date parsing");

         const std::vector<uint32_t> d = parse_date(get_req_str(vars, "Date"));

         if(type == "valid" || type == "valid.not_std")
            {
            Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]);
            result.test_is_eq("year", c.year, d[0]);
            result.test_is_eq("month", c.month, d[1]);
            result.test_is_eq("day", c.day, d[2]);
            result.test_is_eq("hour", c.hour, d[3]);
            result.test_is_eq("minute", c.minutes, d[4]);
            result.test_is_eq("second", c.seconds, d[5]);

            if(type == "valid.not_std")
               {
               result.test_throws("valid but out of std::timepoint range", [c]() { c.to_std_timepoint(); });
               }
            else
               {
               Botan::calendar_point c2 = Botan::calendar_value(c.to_std_timepoint());
               result.test_is_eq("year", c2.year, d[0]);
               result.test_is_eq("month", c2.month, d[1]);
               result.test_is_eq("day", c2.day, d[2]);
               result.test_is_eq("hour", c2.hour, d[3]);
               result.test_is_eq("minute", c2.minutes, d[4]);
               result.test_is_eq("second", c2.seconds, d[5]);
               }
            }
         else if(type == "invalid")
            {
            result.test_throws("invalid date",
                               [d]() { Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]); });
            }
         else
            {
            throw std::runtime_error("Unexpected header '" + type + "' in date format tests");
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("util_dates", Date_Format_Tests);

#if defined(BOTAN_HAS_BASE64_CODEC)

class Base64_Tests : public Text_Based_Test
   {
   public:
      Base64_Tests() : Text_Based_Test(Test::data_file("base64.vec"),
                                       std::vector<std::string>({"Base64"}),
                                       {"Binary"})
         {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("Base64");

         const bool is_valid = (type == "valid");
         const std::string base64 = get_req_str(vars, "Base64");

         try
            {
            if(is_valid)
               {
               const std::vector<byte> binary = get_req_bin(vars, "Binary");
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
               catch(std::exception& e) {}

               try
                  {
                  result.test_eq("base64 decoding with whitespace", Botan::base64_decode(b64_ws, true), "66");
                  }
               catch(std::exception& e)
                  {
                  result.test_failure(b64_ws.c_str(), e.what());
                  }
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("base64", Base64_Tests);

#endif

}

}
