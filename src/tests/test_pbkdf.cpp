/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/pbkdf.h>
#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

size_t test_pbkdf()
   {
   auto test = [](const std::string& input)
      {
      return run_tests(input, "PBKDF", "Output", true,
             [](std::map<std::string, std::string> vec)
             {
             std::unique_ptr<PBKDF> pbkdf(get_pbkdf(vec["PBKDF"]));

             const size_t iterations = to_u32bit(vec["Iterations"]);
             const size_t outlen = to_u32bit(vec["OutputLen"]);
             const auto salt = hex_decode(vec["Salt"]);
             const std::string pass = vec["Passphrase"];

             const auto key = pbkdf->derive_key(outlen, pass,
                                                salt.data(), salt.size(),
                                                iterations).bits_of();
             return hex_encode(key);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "pbkdf", test);
   }
