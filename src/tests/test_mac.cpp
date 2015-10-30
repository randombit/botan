/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MAC)

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
   const std::vector<std::string> providers = MessageAuthenticationCode::providers(algo);
   size_t fails = 0;

   if(providers.empty())
      return warn_about_missing("MAC " + algo);

   for(auto provider: providers)
      {
      std::unique_ptr<MessageAuthenticationCode> mac(MessageAuthenticationCode::create(algo, provider));

      if(!mac)
         {
         fails += warn_about_missing("MAC " + algo + " from " + provider);
         continue;
         }

      const std::vector<byte> in = hex_decode(in_hex);
      const std::vector<byte> exp = hex_decode(out_hex);

      mac->set_key(hex_decode(key_hex));

      mac->update(in);

      fails += test_buffers_equal(algo, provider, "mac", mac->final(), exp);

      if(in.size() > 2)
         {
         mac->set_key(hex_decode(key_hex));
         mac->update(in[0]);
         mac->update(&in[1], in.size() - 2);
         mac->update(in[in.size()-1]);

         fails += test_buffers_equal(algo, provider, "mac2", mac->final(), exp);
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
