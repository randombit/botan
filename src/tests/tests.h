/*
* (C) 2014,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_H__
#define BOTAN_TESTS_H__

#include <botan/build.h>
#include <botan/rng.h>
#include <botan/hex.h>
#include <botan/symkey.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_BIGINT)
  #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
  #include <botan/point_gfp.h>
#endif

#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace Botan_Tests {

using Botan::byte;

#if defined(BOTAN_HAS_BIGINT)
using Botan::BigInt;
#endif

using Botan::OctetString;

class Test_Error : public Botan::Exception
   {
   public:
      explicit Test_Error(const std::string& what) : Exception("Test error", what) {}
   };

/*
* A generic test which retuns a set of results when run.
* The tests may not all have the same type (for example test
* "block" returns results for "AES-128" and "AES-256").
*
* For most test cases you want Text_Based_Test derived below
*/
class Test
   {
   public:

      /*
      * Some number of test results, all associated with who()
      */
      class Result
         {
         public:
            explicit Result(const std::string& who) : m_who(who) {}

            size_t tests_passed() const { return m_tests_passed; }
            size_t tests_failed() const { return m_fail_log.size(); }
            size_t tests_run() const { return tests_passed() + tests_failed(); }
            bool any_results() const { return tests_run() > 0; }

            const std::string& who() const { return m_who; }
            std::string result_string(bool verbose) const;

            static Result Failure(const std::string& who,
                                  const std::string& what)
               {
               Result r(who);
               r.test_failure(what);
               return r;
               }

            static Result Note(const std::string& who,
                               const std::string& what)
               {
               Result r(who);
               r.test_note(what);
               return r;
               }

            static Result OfExpectedFailure(bool expecting_failure,
                                            const Test::Result& result)
               {
               if(!expecting_failure)
                  {
                  return result;
                  }

               if(result.tests_failed() == 0)
                  {
                  Result r = result;
                  r.test_failure("Expected this test to fail, but it did not");
                  return r;
                  }
               else
                  {
                  Result r(result.who());
                  r.test_note("Got expected failure");
                  return r;
                  }
               }

            void merge(const Result& other);

            void test_note(const std::string& note, const char* extra = nullptr);

            template<typename Alloc>
            void test_note(const std::string& who, const std::vector<uint8_t, Alloc>& vec)
               {
               const std::string hex = Botan::hex_encode(vec);
               return test_note(who, hex.c_str());
               }

            void note_missing(const std::string& thing);

            bool test_success(const std::string& note = "");

            bool test_failure(const std::string& err);

            bool test_failure(const std::string& what, const std::string& error);

            void test_failure(const std::string& what, const uint8_t buf[], size_t buf_len);

            template<typename Alloc>
            void test_failure(const std::string& what, const std::vector<uint8_t, Alloc>& buf)
               {
               test_failure(what, buf.data(), buf.size());
               }

            bool confirm(const std::string& what, bool expr)
               {
               return test_eq(what, expr, true);
               }

            template<typename T>
            bool test_is_eq(const T& produced, const T& expected)
               {
               return test_is_eq("comparison", produced, expected);
               }

            template<typename T>
            bool test_is_eq(const std::string& what, const T& produced, const T& expected)
               {
               std::ostringstream out;
               out << m_who << " " << what;

               if(produced == expected)
                  {
                  out << " produced expected result " << produced;
                  return test_success(out.str());
                  }
               else
                  {
                  out << " produced unexpected result " << produced << " expected " << expected;
                  return test_failure(out.str());
                  }
               }

            bool test_eq(const std::string& what, const char* produced, const char* expected);

            bool test_is_nonempty(const std::string& what_is_it, const std::string& to_examine);

            bool test_eq(const std::string& what,
                         const std::string& produced,
                         const std::string& expected);

            bool test_eq(const std::string& what, bool produced, bool expected);

            bool test_eq(const std::string& what, size_t produced, size_t expected);

            bool test_eq(const std::string& what, OctetString produced, OctetString expected);

            template<typename I1, typename I2>
            bool test_int_eq(I1 x, I2 y, const char* what)
               {
               return test_eq(what, static_cast<size_t>(x), static_cast<size_t>(y));
               }

            bool test_lt(const std::string& what, size_t produced, size_t expected);
            bool test_gte(const std::string& what, size_t produced, size_t expected);

            template<typename T>
            bool test_rc_ok(const std::string& func, T rc)
               {
               static_assert(std::is_integral<T>::value, "Integer required.");

               if(rc != 0)
                  {
                  std::ostringstream err;
                  err << m_who;
                  err << " " << func;
                  err << " unexpectedly failed with error code " << rc;
                  return test_failure(err.str());
                  }

               return test_success();
               }

            template<typename T>
            bool test_rc_fail(const std::string& func, const std::string& why, T rc)
               {
               static_assert(std::is_integral<T>::value, "Integer required.");

               if(rc == 0)
                  {
                  std::ostringstream err;
                  err << m_who;
                  err << " call to " << func << " unexpectedly succeeded";
                  err << " expecting failure because " << why;
                  return test_failure(err.str());
                  }

               return test_success();
               }

            bool test_rc(const std::string& func, int expected, int rc);

            bool test_ne(const std::string& what, size_t produced, size_t expected);

#if defined(BOTAN_HAS_BIGINT)
            bool test_eq(const std::string& what, const BigInt& produced, const BigInt& expected);
            bool test_ne(const std::string& what, const BigInt& produced, const BigInt& expected);
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
            bool test_eq(const std::string& what,
                         const Botan::PointGFp& a,
                         const Botan::PointGFp& b);
#endif

            bool test_eq(const char* producer, const std::string& what,
                         const uint8_t produced[], size_t produced_len,
                         const uint8_t expected[], size_t expected_len);

            bool test_ne(const std::string& what,
                         const uint8_t produced[], size_t produced_len,
                         const uint8_t expected[], size_t expected_len);

            template<typename Alloc1, typename Alloc2>
            bool test_eq(const std::string& what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected)
               {
               return test_eq(nullptr, what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            template<typename Alloc1, typename Alloc2>
            bool test_eq(const std::string& producer, const std::string& what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected)
               {
               return test_eq(producer.c_str(), what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            template<typename Alloc>
            bool test_eq(const std::string& what,
                         const std::vector<uint8_t, Alloc>& produced,
                         const char* expected_hex)
               {
               const std::vector<byte> expected = Botan::hex_decode(expected_hex);
               return test_eq(nullptr, what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            template<typename Alloc1, typename Alloc2>
            bool test_ne(const std::string& what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected)
               {
               return test_ne(what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            bool test_throws(const std::string& what, std::function<void ()> fn);
            
            bool test_throws(const std::string& what, const std::string& expected,
                              std::function<void ()> fn);

            void set_ns_consumed(uint64_t ns) { m_ns_taken = ns; }

            void start_timer();
            void end_timer();

         private:
            std::string m_who;
            uint64_t m_started = 0;
            uint64_t m_ns_taken = 0;
            size_t m_tests_passed = 0;
            std::vector<std::string> m_fail_log;
            std::vector<std::string> m_log;
         };

      class Registration
         {
         public:
            Registration(const std::string& name, Test* test);
         };

      virtual std::vector<Test::Result> run() = 0;
      virtual ~Test() {}

      static std::vector<Test::Result> run_test(const std::string& what, bool fail_if_missing);

      static std::map<std::string, std::unique_ptr<Test>>& global_registry();

      static std::set<std::string> registered_tests();

      static Test* get_test(const std::string& test_name);

      static std::string data_file(const std::string& what);

      template<typename Alloc>
      static std::vector<uint8_t, Alloc>
      mutate_vec(const std::vector<uint8_t, Alloc>& v, bool maybe_resize = false)
         {
         auto& rng = Test::rng();

         std::vector<uint8_t, Alloc> r = v;

         if(maybe_resize && (r.empty() || rng.next_byte() < 32))
            {
            // TODO: occasionally truncate, insert at random index
            const size_t add = 1 + (rng.next_byte() % 16);
            r.resize(r.size() + add);
            rng.randomize(&r[r.size() - add], add);
            }

         if(r.size() > 0)
            {
            const size_t offset = rng.next_byte() % r.size();
            r[offset] ^= rng.next_nonzero_byte();
            }

         return r;
         }

      static void setup_tests(size_t soak,
                              bool log_succcss,
                              const std::string& data_dir,
                              const std::string& pkcs11_lib,
                              Botan::RandomNumberGenerator* rng);

      static size_t soak_level();
      static bool log_success();
      static std::string pkcs11_lib();

      static const std::string& data_dir();

      static Botan::RandomNumberGenerator& rng();
      static std::string random_password();
      static uint64_t timestamp(); // nanoseconds arbitrary epoch

   private:
      static std::string m_data_dir;
      static Botan::RandomNumberGenerator* m_test_rng;
      static size_t m_soak_level;
      static bool m_log_success;
      static std::string m_pkcs11_lib;
   };

/*
* Register the test with the runner
*/
#define BOTAN_REGISTER_TEST(type, Test_Class) \
   namespace { Test::Registration reg_ ## Test_Class ## _tests(type, new Test_Class); } \
   BOTAN_FORCE_SEMICOLON

/*
* A test based on reading an input file which contains key/value pairs
* Special note: the last value in required_key (there must be at least
* one), is the output key. This triggers the callback.
*
* Calls run_one_test with the variables set. If an ini-style [header]
* is used in the file, then header will be set to that value. This allows
* splitting up tests between [valid] and [invalid] tests, or different
* related algorithms tested in the same file. Use the protected get_XXX
* functions to retrieve formatted values from the VarMap
*
* If most of your tests are text-based but you find yourself with a few
* odds-and-ends tests that you want to do, override run_final_tests which
* can test whatever it likes and returns a vector of Results.
*/
class Text_Based_Test : public Test
   {
   public:
      Text_Based_Test(const std::string& input_file,
                      const std::vector<std::string>& required_keys,
                      const std::vector<std::string>& optional_keys = {});

      Text_Based_Test(const std::string& algo,
                      const std::string& input_file,
                      const std::vector<std::string>& required_keys,
                      const std::vector<std::string>& optional_keys = {});

      virtual bool clear_between_callbacks() const { return true; }

      std::vector<Test::Result> run() override;
   protected:
      typedef std::unordered_map<std::string, std::string> VarMap;
      std::string get_next_line();

      virtual Test::Result run_one_test(const std::string& header,
                                        const VarMap& vars) = 0;

      virtual std::vector<Test::Result> run_final_tests() { return std::vector<Test::Result>(); }

      std::vector<uint8_t> get_req_bin(const VarMap& vars, const std::string& key) const;
      std::vector<uint8_t> get_opt_bin(const VarMap& vars, const std::string& key) const;

#if defined(BOTAN_HAS_BIGINT)
      Botan::BigInt get_req_bn(const VarMap& vars, const std::string& key) const;
#endif

      std::string get_req_str(const VarMap& vars, const std::string& key) const;
      std::string get_opt_str(const VarMap& vars,
                              const std::string& key,
                              const std::string& def_value) const;

      size_t get_req_sz(const VarMap& vars, const std::string& key) const;
      size_t get_opt_sz(const VarMap& vars, const std::string& key, const size_t def_value) const;

      std::string algo_name() const { return m_algo; }
   private:
      std::string m_algo;
      std::string m_data_src;
      std::set<std::string> m_required_keys;
      std::set<std::string> m_optional_keys;
      std::string m_output_key;

      bool m_first = true;
      std::unique_ptr<std::ifstream> m_cur;
      std::string m_cur_src_name;
      std::deque<std::string> m_srcs;
      std::vector<Botan::CPUID::CPUID_bits> m_cpu_flags;
   };

}

#endif
