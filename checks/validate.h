
#ifndef BOTAN_TEST_VALIDATE_H__
#define BOTAN_TEST_VALIDATE_H__

#include <botan/types.h>
#include <botan/rng.h>
#include <string>
#include <functional>
#include <istream>
#include <map>

using Botan::RandomNumberGenerator;

using Botan::u32bit;

u32bit do_validation_tests(const std::string&,
                           RandomNumberGenerator& rng,
                           bool = true);

u32bit do_bigint_tests(const std::string&,
                       RandomNumberGenerator& rng);

u32bit do_pk_validation_tests(const std::string&,
                              RandomNumberGenerator&);

void do_ec_tests(RandomNumberGenerator& rng);

u32bit do_ecdsa_tests(RandomNumberGenerator& rng);
u32bit do_ecdh_tests(RandomNumberGenerator& rng);
u32bit do_cvc_tests(RandomNumberGenerator& rng);

void do_x509_tests(RandomNumberGenerator&);

size_t do_tls_tests(RandomNumberGenerator& rng);

void test_ocb();

void test_hkdf();
void test_pbkdf();
void test_kdf();
void test_aead();
void test_transform();

void run_tests_bb(std::istream& src,
                  const std::string& name_key,
                  const std::string& output_key,
                  bool clear_between_cb,
                  std::function<bool (std::map<std::string, std::string>)> cb);

void run_tests(std::istream& src,
               const std::string& name_key,
               const std::string& output_key,
               bool clear_between_cb,
               std::function<std::string (std::map<std::string, std::string>)> cb);

#endif
