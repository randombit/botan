/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hash.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t hash_test(const std::string& algo,
                 const std::vector<byte>& input,
                 const std::vector<byte>& expected)
   {
   const std::vector<std::string> providers = HashFunction::providers(algo);

   if(providers.empty())
      return warn_about_missing("hash " + algo);

   size_t fails = 0;

   for(auto provider: providers)
      {
      std::unique_ptr<HashFunction> hash(HashFunction::create(algo, provider));

      if(!hash)
         {
         fails += warn_about_missing(algo + " from " + provider);
         continue;
         }

      hash->update(input);

      fails += test_buffers_equal(algo, provider, "hashing", hash->final(), expected);

      // Test to make sure clear() resets what we need it to
      hash->update("some discarded input");
      hash->clear();
      hash->update(nullptr, 0); // this should be effectively ignored
      hash->update(input);

      fails += test_buffers_equal(algo, provider, "hashing after clear", hash->final(), expected);

      if(input.size() > 1)
         {
         hash->update(input[0]);
         hash->update(&input[1], input.size() - 1);

         fails += test_buffers_equal(algo, provider, "hashing split", hash->final(), expected);
         }
      }

   return fails;
   }

}

size_t test_hash()
   {
   auto test = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "Hash", "Out", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return hash_test(m["Hash"], hex_decode(m["In"]),
                              hex_decode(m["Out"]));
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/hash", test);
   }
