
#ifndef BOTAN_TEST_VALIDATE_H__
#define BOTAN_TEST_VALIDATE_H__

#include <botan/types.h>
#include <botan/rng.h>
#include <string>

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

#endif
