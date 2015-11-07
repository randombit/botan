
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

#if defined(BOTAN_HAS_BIGINT)
  #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
  #include <botan/point_gfp.h>
#endif

#include <map>
#include <string>
#include <vector>
#include <set>
#include <memory>
#include <fstream>

namespace Botan_Tests {

using Botan::byte;

#if defined(BOTAN_HAS_BIGINT)
using Botan::BigInt;
#endif

class Test
   {
   public:
      class Result
         {
         public:
            Result(const std::string& who = "") : m_who(who) {}

            size_t tests_passed() const { return m_tests_passed; }
            size_t tests_failed() const { return m_fail_log.size(); }
            size_t tests_run() const { return tests_passed() + tests_failed(); }
            bool any_results() const { return tests_run() > 0; }

            const std::string& who() const { return m_who; }
            std::string result_string() const;

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

            void merge(const Result& other);

            void test_note(const std::string& note);

            void note_missing(const std::string& thing);

            bool test_success();

            bool test_failure(const std::string& err);

            bool test_failure(const char* what, const char* error);

            void test_failure(const char* what, const uint8_t buf[], size_t buf_len);

            template<typename Alloc>
            void test_failure(const char* what, const std::vector<uint8_t, Alloc>& buf)
               {
               test_failure(what, buf.data(), buf.size());
               }

            bool confirm(const char* what, bool expr)
               {
               return test_eq(what, expr, true);
               }

            bool test_eq(const char* what, const std::string& produced, const std::string& expected);
            bool test_eq(const char* what, bool produced, bool expected);

            bool test_eq(const char* what, size_t produced, size_t expected);
            bool test_lt(const char* what, size_t produced, size_t expected);
            bool test_gte(const char* what, size_t produced, size_t expected);

#if defined(BOTAN_HAS_BIGINT)
            bool test_eq(const char* what, const BigInt& produced, const BigInt& expected);
            bool test_ne(const char* what, const BigInt& produced, const BigInt& expected);
#endif

#if defined(BOTAN_HAS_EC_CURVE_GFP)
            bool test_eq(const char* what, const Botan::PointGFp& a, const Botan::PointGFp& b);
#endif

            bool test_eq(const char* producer, const char* what,
                         const uint8_t produced[], size_t produced_len,
                         const uint8_t expected[], size_t expected_len);

            bool test_ne(const char* what,
                         const uint8_t produced[], size_t produced_len,
                         const uint8_t expected[], size_t expected_len);

            template<typename Alloc1, typename Alloc2>
            bool test_eq(const char* what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected)
               {
               return test_eq(nullptr, what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            template<typename Alloc1, typename Alloc2>
            bool test_eq(const std::string& producer, const char* what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected)
               {
               return test_eq(producer.c_str(), what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            template<typename Alloc1, typename Alloc2>
            bool test_ne(const char* what,
                         const std::vector<uint8_t, Alloc1>& produced,
                         const std::vector<uint8_t, Alloc2>& expected)
               {
               return test_ne(what,
                              produced.data(), produced.size(),
                              expected.data(), expected.size());
               }

            void set_ns_consumed(uint64_t ns) { m_ns_taken = ns; }

         private:
            std::string m_who;
            uint64_t m_ns_taken = 0;
            size_t m_tests_passed = 0;
            std::vector<std::string> m_fail_log;
            std::vector<std::string> m_log;
         };

      class Registration
         {
         public:
            Registration(const std::string& name, Test* test)
               {
               // TODO: check for dups
               Test::global_registry().insert(std::make_pair(name, test));
               }
         };

      virtual std::vector<Test::Result> run() = 0;
      virtual ~Test() {}

      static std::vector<Test::Result> run_test(const std::string& what, bool fail_if_missing);

      static size_t run_tests(const std::vector<std::string>& requested,
                              bool run_all_others,
                              std::ostream& out);

      static std::map<std::string, Test*>& global_registry();

      static std::set<std::string> registered_tests();

      static Test* get_test(const std::string& test_name);

      static std::string data_dir(const std::string& what);
      static std::string data_file(const std::string& what);

      template<typename Alloc>
      static std::vector<uint8_t, Alloc> mutate_vec(const std::vector<uint8_t, Alloc>& v, bool maybe_resize = false)
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
            const size_t offset = rng.get_random<uint16_t>() % r.size();
            r[offset] ^= rng.next_nonzero_byte();
            }

         return r;
         }

      static size_t soak_level();

      static Botan::RandomNumberGenerator& rng();
      static std::string random_password();
   };

#define BOTAN_REGISTER_TEST(type, Test_Class) namespace { Test::Registration reg_ ## Test_Class ## _tests(type, new Test_Class); }

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
      typedef std::map<std::string, std::string> VarMap;
      std::string get_next_line();

      virtual Test::Result run_one_test(const std::string& algo,
                                        const VarMap& vars) = 0;

      std::vector<uint8_t> get_req_bin(const VarMap& vars, const std::string& key) const;
      std::vector<uint8_t> get_opt_bin(const VarMap& vars, const std::string& key) const;

#if defined(BOTAN_HAS_BIGINT)
      Botan::BigInt get_req_bn(const VarMap& vars, const std::string& key) const;
#endif

      std::string get_req_str(const VarMap& vars, const std::string& key) const;
      std::string get_opt_str(const VarMap& vars, const std::string& key, const std::string& def_value) const;

      size_t get_req_sz(const VarMap& vars, const std::string& key) const;
      size_t get_opt_sz(const VarMap& vars, const std::string& key, const size_t def_value) const;

      std::string algo_name() const { return m_algo; }
   private:
      std::string m_algo;
      std::string m_data_dir;
      std::set<std::string> m_required_keys;
      std::set<std::string> m_optional_keys;
      std::string m_output_key;
      bool m_clear_between_cb = false;

      bool m_first = true;
      std::unique_ptr<std::ifstream> m_cur;
      std::deque<std::string> m_srcs;
   };

}

#define TEST_DATA_DIR     "src/tests/data"
#define TEST_DATA_DIR_PK  "src/tests/data/pubkey"
#define TEST_DATA_DIR_ECC "src/tests/data/ecc"

#define TEST_OUTDATA_DIR  "src/tests/outdata"

#endif
