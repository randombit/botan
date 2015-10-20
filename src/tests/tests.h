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
#include <functional>
#include <istream>
#include <map>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

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
