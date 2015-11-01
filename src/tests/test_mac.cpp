/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MAC)
  #include <botan/mac.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_MAC)

class Message_Auth_Tests : public Text_Based_Test
   {
   public:
      Message_Auth_Tests(const std::string& data_dir) :
         Text_Based_Test(data_dir, {"Key", "In", "Out"}) {}

      Test::Result run_one_test(const std::string& algo,
                                const std::map<std::string, std::string>& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = Botan::MessageAuthenticationCode::providers(algo);

         if(providers.empty())
            {
            warn_about_missing("block cipher " + algo);
            return result;
            }

         for(auto&& provider: providers)
            {
            std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create(algo, provider));

            if(!mac)
               {
               warn_about_missing(algo + " from " + provider);
               continue;
               }

            mac->set_key(key);

            mac->update(input);

            result.test_eq(provider, "correct mac", mac->final(), expected);

            if(input.size() > 2)
               {
               mac->set_key(key); // for poly1305
               mac->update(input[0]);
               mac->update(&input[1], input.size() - 2);
               mac->update(input[input.size()-1]);

               result.test_eq(provider, "split mac", mac->final(), expected);
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("mac", Message_Auth_Tests(TEST_DATA_DIR "/mac"));

#endif

}

}

size_t test_mac()
   {
   using namespace Botan_Tests;

   std::vector<Test::Result> results = Test::run_test("mac");

   std::string report;
   size_t fail_cnt = 0;
   Test::summarize(results, report, fail_cnt);

   std::cout << report;
   return fail_cnt;
   }
