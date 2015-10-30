/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t block_test(const std::string& algo,
                  const std::vector<byte>& key,
                  const std::vector<byte>& input,
                  const std::vector<byte>& expected)
   {
   const std::vector<std::string> providers = BlockCipher::providers(algo);

   if(providers.empty())
      return warn_about_missing("block cipher " + algo);

   size_t fails = 0;

   for(auto provider: providers)
      {
      std::unique_ptr<BlockCipher> cipher(BlockCipher::create(algo, provider));

      if(!cipher)
         {
         fails += warn_about_missing(algo + " from " + provider);
         continue;
         }

      cipher->set_key(key);
      std::vector<byte> buf = input;

      cipher->encrypt(buf);

      fails += test_buffers_equal(algo + " " + provider, "encrypt", buf, expected);

      // always decrypt expected ciphertext vs what we produced above
      buf = expected;
      cipher->decrypt(buf);

      fails += test_buffers_equal(algo + " " + provider, "decrypt", buf, input);
      }

   return fails;
   }

}

size_t test_block()
   {
   auto test_bc = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "BlockCipher", "Out", true,
                          [](std::map<std::string, std::string> m) -> size_t
                          {
                          return block_test(m["BlockCipher"], hex_decode(m["Key"]),
                                            hex_decode(m["In"]),
                                            hex_decode(m["Out"]));
                          });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/block", test_bc);
   }
