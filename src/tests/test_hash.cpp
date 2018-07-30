/*
* (C) 2014,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HASH)

namespace {

class Invalid_Hash_Name_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("Invalid HashFunction names");
         test_invalid_name(result, "NonExistentHash");
         test_invalid_name(result, "Blake2b(9)", "Bad output bits size for Blake2b");
         test_invalid_name(result, "Comb4P(MD5,MD5)", "Comb4P: Must use two distinct hashes");
         test_invalid_name(result, "Comb4P(MD5,SHA-256)", "Comb4P: Incompatible hashes MD5 and SHA-256");
         test_invalid_name(result, "Tiger(168)", "Tiger: Illegal hash output size: 168");
         test_invalid_name(result, "Tiger(20,2)", "Tiger: Invalid number of passes: 2");
         test_invalid_name(result, "Keccak-1600(160)", "Keccak_1600: Invalid output length 160");
         test_invalid_name(result, "SHA-3(160)", "SHA_3: Invalid output length 160");

         return {result};
         }

   private:
      void test_invalid_name(Result& result,
                             const std::string& name,
                             const std::string& expected_msg = "") const
         {
         try
            {
            auto hash = Botan::HashFunction::create_or_throw(name);
            result.test_failure("Was successfully able to create " + name);
            }
         catch(Botan::Invalid_Argument& e)
            {
            const std::string msg = e.what();
            const std::string full_msg = "Invalid argument " + expected_msg;
            result.test_eq("expected error message", msg, full_msg);
            }
         catch(Botan::Lookup_Error& e)
            {
            const std::string algo_not_found_msg = "Unavailable Hash " + name;
            const std::string msg = e.what();
            result.test_eq("expected error message", msg, algo_not_found_msg);
            }
         catch(std::exception& e)
            {
            result.test_failure("some unknown exception", e.what());
            }
         catch(...)
            {
            result.test_failure("some unknown exception");
            }
         }
   };

BOTAN_REGISTER_TEST("invalid_name_hash", Invalid_Hash_Name_Tests);

class Hash_Function_Tests final : public Text_Based_Test
   {
   public:
      Hash_Function_Tests() : Text_Based_Test("hash", "In,Out") {}

      std::vector<std::string> possible_providers(const std::string& algo) override
         {
         return provider_filter(Botan::HashFunction::providers(algo));
         }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> input    = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty())
            {
            result.note_missing("hash " + algo);
            return result;
            }

         for(auto const& provider_ask : providers)
            {
            std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(algo, provider_ask));

            if(!hash)
               {
               result.test_failure("Hash " + algo + " supported by " + provider_ask + " but not found");
               continue;
               }

            std::unique_ptr<Botan::HashFunction> clone(hash->clone());

            const std::string provider(hash->provider());
            result.test_is_nonempty("provider", provider);
            result.test_eq(provider, hash->name(), algo);
            result.test_eq(provider, hash->name(), clone->name());

            hash->update(input);
            result.test_eq(provider, "hashing", hash->final(), expected);

            clone->update(input);
            result.test_eq(provider, "hashing (clone)", clone->final(), expected);

            // Test to make sure clear() resets what we need it to
            hash->update("some discarded input");
            hash->clear();
            hash->update(nullptr, 0); // this should be effectively ignored
            hash->update(input);

            result.test_eq(provider, "hashing after clear", hash->final(), expected);

            if(input.size() > 5 && hash->provider() != "af_alg")
               {
               hash->update(input[0]);

               std::unique_ptr<Botan::HashFunction> fork = hash->copy_state();
               // verify fork copy doesn't affect original computation
               fork->update(&input[1], input.size() - 2);

               size_t so_far = 1;
               while(so_far < input.size())
                  {
                  size_t take = Test::rng().next_byte() % (input.size() - so_far);

                  if(input.size() - so_far == 1)
                     take = 1;

                  hash->update(&input[so_far], take);
                  so_far += take;
                  }
               result.test_eq(provider, "hashing split", hash->final(), expected);

               fork->update(&input[input.size() - 1], 1);
               result.test_eq(provider, "hashing split", fork->final(), expected);
               }

            if(hash->hash_block_size() > 0)
               {
               // GOST-34.11 uses 32 byte block
               result.test_gte("If hash_block_size is set, it is large", hash->hash_block_size(), 32);
               }
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("hash", Hash_Function_Tests);

}

#endif

}
