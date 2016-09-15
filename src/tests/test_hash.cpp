/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hash.h>

#if defined (BOTAN_HAS_PARALLEL_HASH)
  #include <botan/par_hash.h>
#endif

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
            result.note_missing("hash " + algo);
            return result;
            }

         for(auto&& provider_ask : providers)
            {
            std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(algo, provider_ask));

            if(!hash)
               {
               result.note_missing(algo + " from " + provider_ask);
               continue;
               }

            const std::string provider(hash->provider());
            result.test_is_nonempty("provider", provider);
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

#if defined(BOTAN_HAS_PARALLEL_HASH)

Test::Result test_clone()
   {
   Test::Result result("Parallel hash");

   std::string algo = "Parallel(MD5,SHA-160)";
   std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(algo));

   if(!hash)
      {
      result.note_missing(algo);
      return result;
      }

   hash->update("");
   result.test_eq("Parallel hashing", hash->final(), "D41D8CD98F00B204E9800998ECF8427EDA39A3EE5E"
                  "6B4B0D3255BFEF95601890AFD80709");

   std::unique_ptr<Botan::HashFunction> hash_clone(hash->clone());

   hash_clone->clear();
   hash_clone->update("");
   result.test_eq("Parallel hashing (clone)", hash_clone->final(), "D41D8CD98F00B204E9800998ECF8427"
                  "EDA39A3EE5E6B4B0D3255BFEF95601890AFD80709");

   return result;
   }

Test::Result test_ctor()
   {
   Test::Result result("Parallel hash");

   std::unique_ptr<Botan::HashFunction> sha256(Botan::HashFunction::create("SHA-256"));
   if(!sha256)
      {
      result.note_missing("SHA-256");
      return result;
      }

   std::unique_ptr<Botan::HashFunction> sha512(Botan::HashFunction::create("SHA-512"));
   if(!sha512)
      {
      result.note_missing("SHA-512");
      return result;
      }

   std::vector<Botan::HashFunction*> hashes = { sha256.get(), sha512.get() };
   Botan::Parallel par_hash(hashes);

   par_hash.update("");
   result.test_eq("Parallel hashing", par_hash.final(), "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B"
                  "934CA495991B7852B855CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9C"
                  "E47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");

   return result;
   }

class Parallel_Hash_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns =
            {
            test_clone,
            test_ctor
            };

         for(size_t i = 0; i != fns.size(); ++i)
            {
            try
               {
               results.push_back(fns[ i ]());
               }
            catch(std::exception& e)
               {
               results.push_back(Test::Result::Failure("Parallel hash tests " + std::to_string(i), e.what()));
               }
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("par_hash", Parallel_Hash_Tests);

#endif

}

}
