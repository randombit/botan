
#ifndef BOTAN_TESTS_H__
#define BOTAN_TESTS_H__

#include <functional>
#include <istream>
#include <map>
#include <string>
#include <vector>

#include "../common.h"

size_t run_tests_bb(std::istream& src,
                    const std::string& name_key,
                    const std::string& output_key,
                    bool clear_between_cb,
                    std::function<bool (std::map<std::string, std::string>)> cb);

size_t run_tests(std::istream& src,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb);

// Run a list of tests
typedef std::function<size_t ()> test_fn;

size_t run_tests(const std::vector<test_fn>& tests);
void test_report(const std::string& name, size_t ran, size_t failed);

#define TEST(expr, msg) do { if(!(expr)) { ++fails; std::cout << msg; } while(0)

#define CHECKS_DIR "src/test-data/"

int test_main(int argc, char* argv[]);

// Tests using reader framework above
size_t test_block();
size_t test_stream();
size_t test_hash();
size_t test_mac();
size_t test_modes();
size_t test_rngs();
size_t test_hkdf();
size_t test_pbkdf();
size_t test_kdf();
size_t test_aead();
size_t test_transform();

// One off tests
size_t test_ocb();
size_t test_eax();
size_t test_keywrap();
size_t test_bcrypt();
size_t test_passhash9();
size_t test_cryptobox();
size_t test_tss();

// File driven tests
size_t test_bigint();
size_t test_pubkey();
size_t test_pk_keygen();

size_t test_ecc();
size_t test_ecdsa();
size_t test_ecdh();

size_t test_x509();
size_t test_cvc();

size_t test_tls();

size_t test_nist_x509();

#endif
