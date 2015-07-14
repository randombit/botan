/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/block_cipher.h>
#include <botan/lookup.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t block_test(const std::string& algo,
                  const std::string& key_hex,
                  const std::string& in_hex,
                  const std::string& out_hex)
   {
   const secure_vector<byte> key = hex_decode_locked(key_hex);
   const secure_vector<byte> pt = hex_decode_locked(in_hex);
   const secure_vector<byte> ct = hex_decode_locked(out_hex);

   const std::vector<std::string> providers = get_block_cipher_providers(algo);
   size_t fails = 0;

   if(providers.empty())
      throw std::runtime_error("Unknown block cipher " + algo);

   for(auto provider: providers)
      {
      std::unique_ptr<BlockCipher> cipher(get_block_cipher(algo, provider));

      if(!cipher)
         {
         std::cout << "Unable to get " << algo << " from " << provider << std::endl;
         ++fails;
         continue;
         }

      cipher->set_key(key);
      secure_vector<byte> buf = pt;

      cipher->encrypt(buf);

      if(buf != ct)
         {
         std::cout << algo << " " << provider << " enc " << hex_encode(buf) << " != " << out_hex << std::endl;
         ++fails;
         buf = ct;
         }

      cipher->decrypt(buf);

      if(buf != pt)
         {
         std::cout << algo << " " << provider << " dec " << hex_encode(buf) << " != " << out_hex << std::endl;
         ++fails;
         }
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
                          return block_test(m["BlockCipher"], m["Key"], m["In"], m["Out"]);
                          });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/block", test_bc);
   }
