
#ifndef BOTAN_TEST_VALIDATE_H__
#define BOTAN_TEST_VALIDATE_H__

#include <botan/types.h>
#include <botan/rng.h>
#include <string>

using Botan::u32bit;

u32bit do_validation_tests(const std::string&,
                           Botan::RandomNumberGenerator& rng,
                           bool = true);

u32bit do_bigint_tests(const std::string&,
                       Botan::RandomNumberGenerator& rng);

u32bit do_gfpmath_tests(Botan::RandomNumberGenerator& rng);

u32bit do_pk_validation_tests(const std::string&,
                              Botan::RandomNumberGenerator&);
void do_x509_tests(Botan::RandomNumberGenerator&);

#endif
