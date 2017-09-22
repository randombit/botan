/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

namespace Botan_Tests {

/*
* Test the test framework :)
*/

class Test_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         /*
         Notation here is confusing. Idea is the result is the actual
         result of the test. The test_result is the result that is the
         testcase, and should typically be in a failure mode.
         */

         Test::Result result("Test Framework");

         // Test a few success corner cases first

         result.test_throws("throws pi", []() { throw 3.14159; });

         // Test expected failure cases
            {
            Test::Result test_result("Testcase");
            test_result.test_throws("doesn't throw", []() { });
            verify_failure("test_throws", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_failure("explicitly reported failure", std::vector<uint8_t>());
            verify_failure("explicit failure", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_failure("explicitly reported failure", "test error");
            verify_failure("explicit failure", result, test_result);
            }

            {
            verify_failure("explicit failure", result, Test::Result::Failure("test", "failure"));
            }

            {
            Test::Result test_result("Testcase");
            std::vector<uint8_t> vec1(5), vec2(3);
            test_result.test_eq("test vectors equal", vec1, vec2);
            verify_failure("test vectors equal", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            size_t x = 5, y = 6;
            test_result.test_eq("test ints equal", x, y);
            verify_failure("test ints equal", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_is_nonempty("empty", "");
            verify_failure("test_is_nonempty", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_lt("not less", 5, 5);
            verify_failure("test_lt", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_lte("not lte", 6, 5);
            verify_failure("test_lte", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_gte("not gte", 5, 6);
            verify_failure("test_gte", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_ne("string ne", "foo", "foo");
            verify_failure("test_ne", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_rc_ok("test_func", -1);
            verify_failure("test_rc_ok", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_rc("test_func", 0, 5);
            verify_failure("test_rc", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_rc_fail("test_func", "testing", 0);
            verify_failure("test_rc_fail", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_throws("test_throws", "expected msg",
                                    []() { throw std::runtime_error("not the message"); });
            verify_failure("test_throws", result, test_result);
            }

            {
            Test::Result test_result("Testcase");
            test_result.test_throws("test_throws", "expected msg",
                                    []() { throw "not even a std::exception"; });
            verify_failure("test_throws", result, test_result);
            }

         return {result};
         }

   private:
      void verify_failure(const std::string& what,
                          Test::Result& result,
                          const Test::Result& test_result)
         {
         if(test_result.tests_failed() > 0)
            result.test_success("Got expected failure for " + what);
         else
            result.test_failure("Expected test to fail for " + what);
         }
   };

BOTAN_REGISTER_TEST("testcode", Test_Tests);

}
