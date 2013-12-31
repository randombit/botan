#include "tests.h"

#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

secure_vector<byte> kdf(const std::string& algo,
                        size_t outlen,
                        const secure_vector<byte>& secret,
                        const secure_vector<byte>& salt)
   {
   std::unique_ptr<KDF> kdf(get_kdf(algo));
   return kdf->derive_key(outlen, secret, salt);
   }

std::string kdf_test(const std::string& algo,
                     size_t outlen,
                     const std::string& secret,
                     const std::string& salt)
   {
   return hex_encode(kdf(algo, outlen,
                         hex_decode_locked(secret),
                         hex_decode_locked(salt)));
   }

}

size_t test_kdf()
   {
   std::ifstream vec("checks/kdf.vec");

   return run_tests(vec, "KDF", "Output", true,
             [](std::map<std::string, std::string> m)
             {
             return kdf_test(m["KDF"], to_u32bit(m["OutputLen"]),
                             m["Secret"], m["Salt"]);
             });
   }
