#include "tests.h"

#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

size_t test_kdf()
   {
   auto test = [](const std::string& input)
      {
      return run_tests(input, "KDF", "Output", true,
             [](std::map<std::string, std::string> vec)
             {
             std::unique_ptr<KDF> kdf(get_kdf(vec["KDF"]));

             const size_t outlen = to_u32bit(vec["OutputLen"]);
             const auto salt = hex_decode(vec["Salt"]);
             const auto secret = hex_decode(vec["Secret"]);

             const auto key = kdf->derive_key(outlen, secret, salt);

             return hex_encode(key);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "kdf", test);
   }
