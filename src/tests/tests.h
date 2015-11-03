
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

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
  #include <botan/pubkey.h>
#endif

#include <functional>
#include <istream>
#include <map>
#include <string>
#include <vector>

#include <iostream>
#include <fstream>
#include <sstream>

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

            void merge(const Result& other);

            void test_note(const std::string& note);

            bool test_success();

            bool test_failure(const std::string& err);

            bool test_failure(const char* what, const char* error);

            void test_failure(const char* what, const uint8_t buf[], size_t buf_len);

            template<typename Alloc>
            void test_failure(const char* what, const std::vector<uint8_t, Alloc>& buf)
               {
               test_failure(what, buf.data(), buf.size());
               }

            bool test_failure(std::ostringstream& oss)
               {
               return test_failure(oss.str());
               }

            bool test_eq(const char* what, bool produced, bool expected);

            bool test_eq(const char* what, size_t produced, size_t expected);

#if defined(BOTAN_HAS_BIGINT)
            bool test_eq(const char* what, const BigInt& produced, const BigInt& expected);
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

            void set_test_number(size_t n) { m_test_number = n; }

         private:
            std::string m_who;
            size_t m_test_number = 0;
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

      static void summarize(const std::vector<Test::Result>& results,
                            std::string& out_report, size_t& out_fail_cnt);

      static std::map<std::string, Test*>& global_registry();

      static Test* get_test(const std::string& test_name);

      static std::vector<Test::Result> run_test(const std::string& what);

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

         const size_t offset = rng.get_random<uint16_t>() % r.size();
         r[offset] ^= rng.next_nonzero_byte();

         return r;
         }

      static size_t soak_level();

      static Botan::RandomNumberGenerator& rng();
   };

size_t basic_error_report(const std::string& test);

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

      std::vector<uint8_t> get_req_bin(const VarMap& vars,
                                       const std::string& key) const;

#if defined(BOTAN_HAS_BIGINT)
      Botan::BigInt get_req_bn(const VarMap& vars, const std::string& key) const;
#endif

      std::string get_req_str(const VarMap& vars, const std::string& key) const;

      std::vector<uint8_t> get_opt_bin(const VarMap& vars,
                                       const std::string& key) const;

      std::string get_opt_str(const VarMap& vars, const std::string& key, const std::string& def_value) const;

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

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
void check_invalid_signatures(Test::Result& result,
                              Botan::PK_Verifier& verifier,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature);

void check_invalid_ciphertexts(Test::Result& result,
                               Botan::PK_Decryptor& decryptor,
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& ciphertext);

#endif

}


Botan::RandomNumberGenerator& test_rng();

size_t run_tests_bb(std::istream& src,
                    const std::string& name_key,
                    const std::string& output_key,
                    bool clear_between_cb,
                    std::function<size_t (std::map<std::string, std::string>)> cb);

size_t run_tests(std::istream& src,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb);

size_t run_tests(const std::string& filename,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb);

size_t run_tests_in_dir(const std::string& dir, std::function<size_t (const std::string&)> fn);

size_t warn_about_missing(const std::string& whatever);


std::string test_buffers_equal(const std::string& algo,
                               const char* provider,
                               const char* what,
                               const uint8_t produced[],
                               size_t produced_size,
                               const uint8_t expected[],
                               size_t expected_size);

template<typename Alloc1, typename Alloc2>
size_t test_buffers_equal(const std::string& algo,
                          const std::string& provider,
                          const char* what,
                          const std::vector<uint8_t, Alloc1>& produced,
                          const std::vector<uint8_t, Alloc2>& expected)
   {
   const std::string res = test_buffers_equal(algo, provider.c_str(), what,
                                              produced.data(), produced.size(),
                                              expected.data(), expected.size());
   return res.size() > 0;
   }

template<typename Alloc1, typename Alloc2>
size_t test_buffers_equal(const std::string& algo,
                          const char* what,
                          const std::vector<uint8_t, Alloc1>& produced,
                          const std::vector<uint8_t, Alloc2>& expected)
   {
   const std::string res = test_buffers_equal(algo, nullptr, what,
                                            produced.data(), produced.size(),
                                            expected.data(), expected.size());
   return res.size() > 0;
   }

// Run a list of tests
typedef std::function<size_t ()> test_fn;

size_t run_tests(const std::vector<std::pair<std::string, test_fn>>& tests);
void test_report(const std::string& name, size_t ran, size_t failed);

class Test_State
   {
   public:
      void started(const std::string& /*msg*/) { m_tests_run++; }

      void test_ran(const char* msg);

      void failure(const char* test, const std::string& what_failed)
         {
         std::cout << "FAIL " << test << " " << what_failed << "\n";
         m_tests_failed++;
         }

      size_t ran() const { return m_tests_run; }
      size_t failed() const { return m_tests_failed; }
   private:
      size_t m_tests_run = 0, m_tests_failed = 0;
   };

#define BOTAN_CONFIRM_NOTHROW(block) do {                              \
   try { block }                                                        \
   catch(std::exception& e) {                                           \
      _test.failure(BOTAN_CURRENT_FUNCTION, e.what());  \
   } } while(0)                                                         \

#define BOTAN_TEST(lhs, rhs, msg) do {                                     \
   _test.started(msg);                                                  \
   BOTAN_CONFIRM_NOTHROW({                                              \
      const auto lhs_val = lhs;                                         \
      const auto rhs_val = rhs;                                         \
      const bool cmp = lhs_val == rhs_val;                              \
      if(!cmp)                                                          \
         {                                                              \
         std::ostringstream fmt;                                        \
         fmt << "expr '" << #lhs << " == " << #rhs << "' false, "       \
             << "actually " << lhs_val << " " << rhs_val                \
             << " (" << msg << ")";                                     \
         _test.failure(BOTAN_CURRENT_FUNCTION, fmt.str()); \
         }                                                              \
      });                                                               \
   } while(0)

#define BOTAN_CONFIRM(expr, msg) do {                                     \
   _test.started(msg);                                                  \
   BOTAN_CONFIRM_NOTHROW({                                              \
      const bool expr_val = expr;                                         \
      if(!expr_val)                                                     \
         {                                                              \
         std::ostringstream fmt;                                        \
         fmt << "expr '" << #expr << " false (" << msg << ")";           \
         _test.failure(BOTAN_CURRENT_FUNCTION, fmt.str());              \
         }                                                              \
      });                                                               \
   } while(0)

#define BOTAN_TEST_CASE(name, descr, block) size_t test_ ## name() {     \
   Test_State _test;                                                    \
   BOTAN_CONFIRM_NOTHROW(block);                                           \
   test_report(descr, _test.ran(), _test.failed());                     \
   return _test.failed();                                   \
   }

//#define TEST(expr, msg) do { if(!(expr)) { ++fails; std::cout << msg; } while(0)

#define TEST_DATA_DIR     "src/tests/data"
#define TEST_DATA_DIR_PK  "src/tests/data/pubkey"
#define TEST_DATA_DIR_ECC "src/tests/data/ecc"

#define TEST_OUTDATA_DIR  "src/tests/outdata"

int test_main(int argc, char* argv[]);

// Tests using reader framework above
size_t test_block();
size_t test_stream();
size_t test_hash();
size_t test_mac();
size_t test_modes();
size_t test_rngs();
size_t test_pbkdf();
size_t test_kdf();
size_t test_aead();
size_t test_transform();

size_t test_rsa();
size_t test_rw();
size_t test_dsa();
size_t test_nr();
size_t test_dh();
size_t test_dlies();
size_t test_elgamal();
size_t test_ecc_pointmul();
size_t test_ecc_random();
size_t test_ecdsa();
size_t test_gost_3410();
size_t test_curve25519();
size_t test_gf2m();
size_t test_mceliece();
size_t test_mce();

// One off tests
size_t test_ocb();
size_t test_keywrap();
size_t test_bcrypt();
size_t test_passhash9();
size_t test_cryptobox();
size_t test_tss();
size_t test_rfc6979();

size_t test_pk_keygen();

size_t test_bigint();

size_t test_ecc_unit();
size_t test_ecc_randomized();
size_t test_ecdsa_unit();
size_t test_ecdh_unit();

size_t test_x509();
size_t test_x509_x509test();
size_t test_cvc();

size_t test_tls();

size_t test_nist_x509();

size_t test_srp6();
size_t test_compression();

size_t test_fuzzer();

#define SKIP_TEST(testname) \
   size_t test_ ## testname() {                                    \
      std::cout << "Skipping tests: " << # testname  << std::endl; \
      return 0; \
   } \

/*
 * Warn if a test requires loading more modules than necessary to build
 * the lib. E.g.
 *    $ ./configure.py --no-autoload --enable-modules='ocb'
 *    $ make
 *    $ ./botan-test ocb
 * warns the user whereas 
 *    $ ./configure.py --no-autoload --enable-modules='ocb,aes'
 *    $ make
 *    $ ./botan-test ocb
 * runs the test.
 */
#define UNTESTED_WARNING(testname) \
   size_t test_ ## testname() {                                       \
      std::cout << "Skipping tests: " << # testname << std::endl;     \
      std::cout << "WARNING: " << # testname << " has been compiled " \
                << "but is not tested due to other missing modules."  \
                << std::endl; \
      return 0; \
   } \

#endif
