#include "tests.h"

#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

secure_vector<byte> pbkdf(const std::string& algo,
                          const std::string& pass,
                          const secure_vector<byte>& salt,
                          size_t iterations, size_t outlen)
   {
   std::unique_ptr<PBKDF> pbkdf(get_pbkdf(algo));
   return pbkdf->derive_key(outlen, pass,
                            &salt[0], salt.size(),
                            iterations).bits_of();
   }

std::string pbkdf_test(const std::string& algo,
                       const std::string& pass,
                       const std::string& salt,
                       size_t iterations,
                       size_t outlen)
   {
   return hex_encode(pbkdf(algo,
                           pass,
                           hex_decode_locked(salt),
                           iterations,
                           outlen));
   }

}

size_t test_pbkdf()
   {
   std::ifstream vec(CHECKS_DIR "/pbkdf.vec");

   return run_tests(vec, "PBKDF", "Output", true,
             [](std::map<std::string, std::string> m)
             {
             return pbkdf_test(m["PBKDF"], m["Passphrase"], m["Salt"],
                               to_u32bit(m["Iterations"]), to_u32bit(m["OutputLen"]));
             });
   }
