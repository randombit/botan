/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/block_cipher.h>

namespace Botan_Tests {

class Block_Cipher_Tests final : public Text_Based_Test
   {
   public:
      Block_Cipher_Tests() : Text_Based_Test("block", "Key,In,Out", "Iterations") {}

      std::vector<std::string> possible_providers(const std::string& algo) override
         {
         return provider_filter(Botan::BlockCipher::providers(algo));
         }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");
         const size_t iterations             = get_opt_sz(vars, "Iterations", 1);

         Test::Result result(algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty())
            {
            result.note_missing("block cipher " + algo);
            return result;
            }

         for(auto const& provider_ask : providers)
            {
            std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create(algo, provider_ask));

            if(!cipher)
               {
               result.test_failure("Cipher " + algo + " supported by " + provider_ask + " but not found");
               continue;
               }

            const std::string provider(cipher->provider());
            result.test_is_nonempty("provider", provider);
            result.test_eq(provider, cipher->name(), algo);
            result.test_gte(provider, cipher->parallelism(), 1);
            result.test_gte(provider, cipher->block_size(), 8);
            result.test_gte(provider, cipher->parallel_bytes(), cipher->block_size() * cipher->parallelism());

            // Test that trying to encrypt or decrypt with now key set throws Botan::Invalid_State
            try
               {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->encrypt(block);
               result.test_failure("Was able to encrypt without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to encrypt with no key set fails");
               }

            try
               {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->decrypt(block);
               result.test_failure("Was able to decrypt without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to encrypt with no key set fails");
               }

            // Test to make sure clear() resets what we need it to
            cipher->set_key(Test::rng().random_vec(cipher->key_spec().maximum_keylength()));
            Botan::secure_vector<uint8_t> garbage = Test::rng().random_vec(cipher->block_size());
            cipher->encrypt(garbage);
            cipher->clear();

            cipher->set_key(key);

            // Test that clone works and does not affect parent object
            std::unique_ptr<Botan::BlockCipher> clone(cipher->clone());
            result.confirm("Clone has different pointer", cipher.get() != clone.get());
            result.test_eq("Clone has same name", cipher->name(), clone->name());
            clone->set_key(Test::rng().random_vec(cipher->maximum_keylength()));

            // have called set_key on clone: process input values
            std::vector<uint8_t> buf = input;

            for(size_t i = 0; i != iterations; ++i)
               {
               cipher->encrypt(buf);
               }

            result.test_eq(provider, "encrypt", buf, expected);

            // always decrypt expected ciphertext vs what we produced above
            buf = expected;

            for(size_t i = 0; i != iterations; ++i)
               {
               cipher->decrypt(buf);
               }

            cipher->clear();

            result.test_eq(provider, "decrypt", buf, input);

            try
               {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->encrypt(block);
               result.test_failure("Was able to encrypt without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to encrypt with no key set (after clear) fails");
               }

            try
               {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->decrypt(block);
               result.test_failure("Was able to decrypt without a key being set");
               }
            catch(Botan::Invalid_State&)
               {
               result.test_success("Trying to decrypt with no key set (after clear) fails");
               }

            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("block", Block_Cipher_Tests);

}
