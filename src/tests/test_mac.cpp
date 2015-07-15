/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MAC)

#include <botan/lookup.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t mac_test(const std::string& algo,
                const std::string& key_hex,
                const std::string& in_hex,
                const std::string& out_hex)
   {
   const std::vector<std::string> providers = get_mac_providers(algo);
   size_t fails = 0;

   if(providers.empty())
      {
      std::cout << "Unknown algo " << algo << std::endl;
      ++fails;
      }

   for(auto provider: providers)
      {
      std::unique_ptr<MessageAuthenticationCode> mac(get_mac(algo, provider));

      if(!mac)
         {
         std::cout << "Unable to get " << algo << " from " << provider << std::endl;
         ++fails;
         continue;
         }

      const std::vector<byte> in = hex_decode(in_hex);
      const std::vector<byte> exp = hex_decode(out_hex);

      mac->set_key(hex_decode(key_hex));

      mac->update(in);

      const std::vector<byte> out = unlock(mac->final());

      if(out != exp)
         {
         std::cout << algo << " " << provider << " got " << hex_encode(out) << " != " << hex_encode(exp) << std::endl;
         ++fails;
         }

      if(in.size() > 2)
         {
         mac->set_key(hex_decode(key_hex));
         mac->update(in[0]);
         mac->update(&in[1], in.size() - 2);
         mac->update(in[in.size()-1]);

         const std::vector<byte> out2 = unlock(mac->final());

         if(out2 != exp)
            {
            std::cout << algo << " " << provider << " got " << hex_encode(out2) << " != " << hex_encode(exp) << std::endl;
            ++fails;
            }
         }
      }

   return fails;
   }

}

size_t test_mac()
   {
   auto test = [](const std::string& input)
      {
      std::ifstream vec(input);

      return run_tests_bb(vec, "Mac", "Out", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return mac_test(m["Mac"], m["Key"], m["In"], m["Out"]);
             });
      };

   return run_tests_in_dir(TEST_DATA_DIR "/mac", test);
   }

#else

SKIP_TEST(mac);

#endif // BOTAN_HAS_MAC
