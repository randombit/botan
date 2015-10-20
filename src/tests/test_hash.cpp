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
                 const std::string& in_hex,
                 const std::string& out_hex)
   {
   size_t fails = 0;

   const std::vector<std::string> providers = HashFunction::providers(algo);

   if(providers.empty())
      {
      std::cout << "Unknown hash '" << algo << "'" << std::endl;
      return 0;
      }

   for(auto provider: providers)
      {
      std::unique_ptr<HashFunction> hash(HashFunction::create(algo, provider));

      if(!hash)
         {
         std::cout << "Unable to get " << algo << " from " << provider << std::endl;
         ++fails;
         continue;
         }

      const std::vector<byte> in = hex_decode(in_hex);

      hash->update(in);

      auto h = hash->final();

      if(h != hex_decode_locked(out_hex))
         {
         std::cout << algo << " " << provider << " got " << hex_encode(h) << " != " << out_hex << std::endl;
         ++fails;
         }

      // Test to make sure clear() resets what we need it to
      hash->update("some discarded input");
      hash->clear();

      hash->update(in);

      h = hash->final();

      if(h != hex_decode_locked(out_hex))
         {
         std::cout << algo << " " << provider << " got " << hex_encode(h) << " != " << out_hex
                   << " (with discarded input)" << std::endl;
         ++fails;
         }

      if(in.size() > 1)
         {
         hash->update(in[0]);
         hash->update(&in[1], in.size() - 1);
         h = hash->final();

         if(h != hex_decode_locked(out_hex))
            {
            std::cout << algo << " " << provider << " got " << hex_encode(h) << " != " << out_hex
                      << " (with offset input)" << std::endl;
            ++fails;
            }
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
             return hash_test(m["Hash"], m["In"], m["Out"]);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/hash", test);
   }
