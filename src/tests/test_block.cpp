/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/block_cipher.h>

namespace Botan_Tests {

class Block_Cipher_Tests : public Text_Based_Test
   {
   public:
      Block_Cipher_Tests() : Text_Based_Test("block", {"Key", "In", "Out"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = Botan::BlockCipher::providers(algo);

         if(providers.empty())
            {
            result.note_missing("block cipher " + algo);
            return result;
            }

         for(auto&& provider_ask : providers)
            {
            std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create(algo, provider_ask));

            if(!cipher)
               {
               result.note_missing(algo + " from " + provider_ask);
               continue;
               }

            const std::string provider(cipher->provider());
            result.test_is_nonempty("provider", provider);
            result.test_eq(provider, cipher->name(), algo);
            result.test_gte(provider, cipher->parallelism(), 1);
            result.test_gte(provider, cipher->block_size(), 8);
            result.test_gte(provider, cipher->parallel_bytes(), cipher->block_size() * cipher->parallelism());

            // Test to make sure clear() resets what we need it to
            cipher->set_key(Test::rng().random_vec(cipher->key_spec().minimum_keylength()));
            Botan::secure_vector<byte> garbage = Test::rng().random_vec(cipher->block_size());
            cipher->encrypt(garbage);
            cipher->clear();

            cipher->set_key(key);
            std::vector<uint8_t> buf = input;

            cipher->encrypt(buf);

            result.test_eq(provider, "encrypt", buf, expected);

            // always decrypt expected ciphertext vs what we produced above
            buf = expected;
            cipher->decrypt(buf);

            cipher->clear();

            result.test_eq(provider, "decrypt", buf, input);
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("block", Block_Cipher_Tests);

}
