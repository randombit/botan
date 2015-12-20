/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hash.h>

namespace Botan_Tests {

namespace {

class Hash_Function_Tests : public Text_Based_Test
   {
   public:
      Hash_Function_Tests() : Text_Based_Test("hash", {"In", "Out"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = Botan::HashFunction::providers(algo);

         if(providers.empty())
            {
            result.note_missing("block cipher " + algo);
            return result;
            }

         for(auto&& provider: providers)
            {
            std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(algo, provider));

            if(!hash)
               {
               result.note_missing(algo + " from " + provider);
               continue;
               }

            result.test_eq(provider, hash->name(), algo);

            hash->update(input);

            result.test_eq(provider, "hashing", hash->final(), expected);

            // Test to make sure clear() resets what we need it to
            hash->update("some discarded input");
            hash->clear();
            hash->update(nullptr, 0); // this should be effectively ignored
            hash->update(input);

            result.test_eq(provider, "hashing after clear", hash->final(), expected);

            if(input.size() > 1)
               {
               hash->update(input[0]);
               hash->update(&input[1], input.size() - 1);
               result.test_eq(provider, "hashing split", hash->final(), expected);
               }
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("hash", Hash_Function_Tests);

}

}
