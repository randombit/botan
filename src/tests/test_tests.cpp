/*
* (C) 2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

namespace Botan_Tests {

/*
* Test the test framework :)
*/

class Test_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         /*
         Notation here is confusing. Idea is the result is the actual
         result of the test. The test_result is the result that is the
         testcase, and should typically be in a failure mode.
         */

         Test::Result result("Test Framework");

         // Test a few success corner cases first
         const std::string testcase_name = "Failing Test";

         // NOLINTNEXTLINE(hicpp-exception-baseclass)
         result.test_throws("throws pi(-ish)", []() { throw 22.0 / 7; });

         // Test expected failure cases
         {
            Test::Result test_result(testcase_name);
            test_result.test_throws("doesn't throw", []() {});
            verify_failure("test_throws 1", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_failure("explicitly reported failure", std::vector<uint8_t>());
            verify_failure("explicit failure", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_failure("explicitly reported failure", "test error");
            verify_failure("explicit failure", result, test_result);
         }

         { verify_failure("explicit failure", result, Test::Result::Failure(testcase_name, "failure")); }

         {
            Test::Result test_result(testcase_name);
            std::vector<uint8_t> vec1(5), vec2(3, 9);
            test_result.test_eq("test vectors equal", vec1, vec2);
            verify_failure("test vectors equal", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            std::vector<uint8_t> vec1(5), vec2(5);
            test_result.test_ne("test vectors not equal", vec1, vec2);
            verify_failure("test vectors equal", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            std::vector<uint8_t> vec1(5), vec2(5);
            test_result.test_ne("test arrays not equal", vec1.data(), vec1.size(), vec2.data(), vec2.size());
            verify_failure("test vectors equal", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            size_t x = 5, y = 6;
            test_result.test_eq("test ints equal", x, y);
            verify_failure("test ints equal", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            size_t x = 5, y = 5;
            test_result.test_ne("test ints not equal", x, y);
            verify_failure("test ints not equal", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_is_nonempty("empty", "");
            verify_failure("test_is_nonempty", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_lt("not less", 5, 5);
            verify_failure("test_lt", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_lte("not lte", 6, 5);
            verify_failure("test_lte", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_gte("not gte", 5, 6);
            verify_failure("test_gte", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_ne("string ne", "foo", "foo");
            verify_failure("test_ne", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_rc_ok("test_func", -1);
            verify_failure("test_rc_ok", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_rc("test_func", 0, 5);
            verify_failure("test_rc", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_rc_fail("test_func", "testing", 0);
            verify_failure("test_rc_fail", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_throws(
               "test_throws", "expected msg", []() { throw std::runtime_error("not the message"); });
            verify_failure("test_throws 2", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_throws("test_throws", "expected msg", []() {
               // NOLINTNEXTLINE(hicpp-exception-baseclass)
               throw std::string("not even a std::exception");
            });
            verify_failure("test_throws 3", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_throws("test_throws", "expected msg", []() { ; });
            verify_failure("test_throws 4", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_throws<std::invalid_argument>(
               "test_throws", "expected msg", []() { throw std::runtime_error("expected msg"); });
            verify_failure("test_throws 5", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_throws<std::invalid_argument>("test_throws",
                                                           []() { throw std::runtime_error("expected msg"); });
            verify_failure("test_throws 6", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            test_result.test_no_throw("test_no_throw", []() { throw std::runtime_error("boom!"); });
            verify_failure("test_throws 7", result, test_result);
         }

#if defined(BOTAN_HAS_BIGINT)
         {
            Test::Result test_result(testcase_name);
            const auto x = Botan::BigInt::from_word(5);
            const auto y = Botan::BigInt::from_word(6);
            test_result.test_eq("test ints equal", x, y);
            verify_failure("test ints equal", result, test_result);
         }

         {
            Test::Result test_result(testcase_name);
            const auto x = Botan::BigInt::from_word(5);
            const auto y = Botan::BigInt::from_word(5);
            test_result.test_ne("test ints not equal", x, y);
            verify_failure("test ints not equal", result, test_result);
         }
#endif

         return {result, test_testsuite_rng()};
      }

   private:
      static Test::Result test_testsuite_rng() {
         Test::Result result("Testsuite_RNG");

         size_t histogram[256] = {0};

         const size_t RUNS = 1000;

         auto rng = Test::new_rng(__func__);

         for(size_t i = 0; i != 256 * RUNS; ++i) {
            histogram[rng->next_byte()] += 1;
         }

         for(size_t i = 0; i != 256; ++i) {
            if(histogram[i] < RUNS / 2 || histogram[i] > RUNS * 2) {
               result.test_failure("Testsuite_RNG produced non-uniform output");
            } else {
               result.test_success("Testsuite_RNG seemed roughly uniform");
            }
         }

         return result;
      }

      static void verify_failure(const std::string& what, Test::Result& result, const Test::Result& test_result) {
         if(test_result.tests_failed() > 0) {
            result.test_success("Got expected failure for " + what);
            const std::string result_str = test_result.result_string();

            result.confirm("result string contains FAIL", result_str.find("FAIL") != std::string::npos);
         } else {
            result.test_failure("Expected test to fail for " + what);
         }
      }
};

BOTAN_REGISTER_TEST("utils", "testcode", Test_Tests);

}  // namespace Botan_Tests
