/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
   #include <botan/exceptn.h>
   #include <botan/mem_ops.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_BLOCK_CIPHER)

class Block_Cipher_Tests final : public Text_Based_Test {
   public:
      Block_Cipher_Tests() : Text_Based_Test("block", "Key,In,Out", "Tweak,Iterations") {}

      std::vector<std::string> possible_providers(const std::string& algo) override {
         return provider_filter(Botan::BlockCipher::providers(algo));
      }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<uint8_t> tweak = vars.get_opt_bin("Tweak");
         const size_t iterations = vars.get_opt_sz("Iterations", 1);

         Test::Result result(algo);

         if(iterations > 1 && run_long_tests() == false) {
            return result;
         }

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty()) {
            result.note_missing("block cipher " + algo);
            return result;
         }

         for(const auto& provider_ask : providers) {
            auto cipher = Botan::BlockCipher::create(algo, provider_ask);

            if(!cipher) {
               result.test_failure(Botan::fmt("Cipher {} supported by {} but not found", algo, provider_ask));
               continue;
            }

            const std::string provider(cipher->provider());
            result.test_str_not_empty("provider", provider);
            result.test_str_eq(provider, cipher->name(), algo);
            result.test_sz_gte(provider, cipher->parallelism(), 1);
            result.test_sz_gte(provider, cipher->block_size(), 8);
            result.test_sz_gte(provider, cipher->parallel_bytes(), cipher->block_size() * cipher->parallelism());

            result.test_is_false("no key set", cipher->has_keying_material());

            // Test that trying to encrypt or decrypt with no key set throws Botan::Invalid_State
            try {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->encrypt(block);
               result.test_failure("Was able to encrypt without a key being set");
            } catch(Botan::Invalid_State&) {
               result.test_success("Trying to encrypt with no key set fails");
            }

            try {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->decrypt(block);
               result.test_failure("Was able to decrypt without a key being set");
            } catch(Botan::Invalid_State&) {
               result.test_success("Trying to encrypt with no key set fails");
            }

            // Test to make sure clear() resets what we need it to
            cipher->set_key(this->rng().random_vec(cipher->key_spec().maximum_keylength()));
            Botan::secure_vector<uint8_t> garbage = this->rng().random_vec(cipher->block_size());
            cipher->encrypt(garbage);
            cipher->clear();

            /*
            * Different providers may have additional restrictions on key sizes.
            * Avoid testing the cipher with a key size that it does not natively support.
            */
            if(!cipher->valid_keylength(key.size())) {
               result.test_note("Skipping test with provider " + provider + " as it does not support key length " +
                                std::to_string(key.size()));
               continue;
            }

            cipher->set_key(key);
            result.test_is_true("key set", cipher->has_keying_material());

            if(!tweak.empty()) {
               Botan::Tweakable_Block_Cipher* tbc = dynamic_cast<Botan::Tweakable_Block_Cipher*>(cipher.get());
               if(tbc == nullptr) {
                  result.test_failure("Tweak set in test data but cipher is not a Tweakable_Block_Cipher");
               } else {
                  tbc->set_tweak(tweak.data(), tweak.size());
               }
            }

            // Test that clone works and does not affect parent object
            auto clone = cipher->new_object();
            result.test_is_true("Clone has different pointer", cipher.get() != clone.get());
            result.test_str_eq("Clone has same name", cipher->name(), clone->name());
            clone->set_key(this->rng().random_vec(cipher->maximum_keylength()));

            // have called set_key on clone: process input values
            std::vector<uint8_t> buf = input;

            for(size_t i = 0; i != iterations; ++i) {
               cipher->encrypt(buf);
            }

            result.test_bin_eq(provider, "encrypt", buf, expected);

            // always decrypt expected ciphertext vs what we produced above
            buf = expected;

            for(size_t i = 0; i != iterations; ++i) {
               cipher->decrypt(buf);
            }

            result.test_bin_eq(provider, "decrypt", buf, input);

            // Now test misaligned buffers
            const size_t blocks = input.size() / cipher->block_size();
            buf.resize(input.size() + 1);
            Botan::copy_mem(buf.data() + 1, input.data(), input.size());

            for(size_t i = 0; i != iterations; ++i) {
               cipher->encrypt_n(buf.data() + 1, buf.data() + 1, blocks);
            }

            result.test_bin_eq(provider.c_str(),
                               "encrypt misaligned",
                               buf.data() + 1,
                               buf.size() - 1,
                               expected.data(),
                               expected.size());

            // always decrypt expected ciphertext vs what we produced above
            Botan::copy_mem(buf.data() + 1, expected.data(), expected.size());

            for(size_t i = 0; i != iterations; ++i) {
               cipher->decrypt_n(buf.data() + 1, buf.data() + 1, blocks);
            }

            result.test_bin_eq(
               provider.c_str(), "decrypt misaligned", buf.data() + 1, buf.size() - 1, input.data(), input.size());

            result.test_is_true("key set", cipher->has_keying_material());
            cipher->clear();
            result.test_is_false("key set", cipher->has_keying_material());

            try {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->encrypt(block);
               result.test_failure("Was able to encrypt without a key being set");
            } catch(Botan::Invalid_State&) {
               result.test_success("Trying to encrypt with no key set (after clear) fails");
            }

            try {
               std::vector<uint8_t> block(cipher->block_size());
               cipher->decrypt(block);
               result.test_failure("Was able to decrypt without a key being set");
            } catch(Botan::Invalid_State&) {
               result.test_success("Trying to decrypt with no key set (after clear) fails");
            }
         }

         return result;
      }
};

BOTAN_REGISTER_SERIALIZED_SMOKE_TEST("block", "block_ciphers", Block_Cipher_Tests);

class BlockCipher_ParallelOp_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         /*
         * This is somewhat intentionally not a list of all ciphers
         * but rather those that are or are likely in the future to be
         * implemented using some kind of bitslicing or SIMD technique.
         */
         const std::vector<std::string> ciphers = {"AES-128",
                                                   "AES-192",
                                                   "AES-256",
                                                   "ARIA-128",
                                                   "ARIA-256",
                                                   "Camellia-128",
                                                   "Camellia-192",
                                                   "Camellia-256",
                                                   "DES",
                                                   "TripleDES",
                                                   "IDEA",
                                                   "Noekeon",
                                                   "SEED",
                                                   "Serpent",
                                                   "SHACAL2",
                                                   "SM4"};

         std::vector<Test::Result> results;
         results.reserve(ciphers.size());
         for(const auto& cipher : ciphers) {
            results.push_back(test_parallel_op(cipher));
         }
         return results;
      }

   private:
      Test::Result test_parallel_op(const std::string& cipher_name) const {
         Test::Result result(cipher_name + " parallel operation");

         auto cipher = Botan::BlockCipher::create(cipher_name);
         if(cipher == nullptr) {
            result.note_missing(cipher_name);
            return result;
         }

         result.test_sz_gte("Has non-zero parallelism", cipher->parallelism(), 1);

         const size_t block_size = cipher->block_size();

         // Chosen to maximize coverage of handling of tail blocks
         constexpr size_t test_blocks = 128 + 64 + 32 + 16 + 8 + 4 + 2 + 1;

         std::vector<uint8_t> input(block_size * test_blocks);
         rng().randomize(input);

         cipher->set_key(rng().random_vec(cipher->maximum_keylength()));

         // Encrypt the message one block at a time
         std::vector<uint8_t> enc_1by1(input);

         for(size_t i = 0; i != test_blocks; ++i) {
            cipher->encrypt(&enc_1by1[i * block_size], &enc_1by1[i * block_size]);
         }

         // Encrypt the message with all blocks potentially in parallel
         std::vector<uint8_t> enc_all(input);

         cipher->encrypt(enc_all);

         result.test_bin_eq("Same output no matter how encrypted", enc_all, enc_1by1);

         // Decrypt the message one block at a time
         for(size_t i = 0; i != test_blocks; ++i) {
            cipher->decrypt(&enc_1by1[i * block_size], &enc_1by1[i * block_size]);
         }

         // Decrypt the message with all blocks potentially in parallel
         cipher->decrypt(enc_all);

         result.test_bin_eq("Same output no matter how decrypted", enc_all, enc_1by1);
         result.test_bin_eq("Original input recovered in 1-by-1", enc_1by1, input);
         result.test_bin_eq("Original input recovered in parallel processing", enc_all, input);

         return result;
      }
};

BOTAN_REGISTER_TEST("block", "bc_parop", BlockCipher_ParallelOp_Test);

#endif

}  // namespace Botan_Tests
