/*
* (C) 2014,2015,2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HASH)

namespace {

class Invalid_Hash_Name_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Invalid HashFunction names");
         test_invalid_name(result, "NonExistentHash");
         test_invalid_name(result, "Blake2b(9)", "Bad output bits size for BLAKE2b");
         test_invalid_name(result, "Comb4P(MD5,MD5)", "Comb4P: Must use two distinct hashes");
         test_invalid_name(result, "Comb4P(MD5,SHA-256)", "Comb4P: Incompatible hashes MD5 and SHA-256");
         test_invalid_name(result, "Keccak-1600(160)", "Keccak_1600: Invalid output length 160");
         test_invalid_name(result, "SHA-3(160)", "SHA_3: Invalid output length 160");

         return {result};
      }

   private:
      static void test_invalid_name(Result& result, const std::string& name, const std::string& expected_msg = "") {
         try {
            auto hash = Botan::HashFunction::create_or_throw(name);
            result.test_failure("Was successfully able to create " + name);
         } catch(Botan::Invalid_Argument& e) {
            const std::string msg = e.what();
            const std::string full_msg = "" + expected_msg;
            result.test_eq("expected error message", msg, full_msg);
         } catch(Botan::Lookup_Error& e) {
            const std::string algo_not_found_msg = "Unavailable Hash " + name;
            const std::string msg = e.what();
            result.test_eq("expected error message", msg, algo_not_found_msg);
         } catch(std::exception& e) {
            result.test_failure("some unknown exception", e.what());
         } catch(...) {
            result.test_failure("some unknown exception");
         }
      }
};

BOTAN_REGISTER_TEST("hash", "invalid_name_hash", Invalid_Hash_Name_Tests);

class Hash_Function_Tests final : public Text_Based_Test {
   public:
      Hash_Function_Tests() : Text_Based_Test("hash", "In,Out") {}

      std::vector<std::string> possible_providers(const std::string& algo) override {
         return provider_filter(Botan::HashFunction::providers(algo));
      }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty()) {
            result.note_missing("hash " + algo);
            return result;
         }

         for(const auto& provider_ask : providers) {
            auto hash = Botan::HashFunction::create(algo, provider_ask);

            if(!hash) {
               result.test_failure(Botan::fmt("Hash {} supported by {} but not found", algo, provider_ask));
               continue;
            }

            auto clone = hash->new_object();

            const std::string provider(hash->provider());
            result.test_is_nonempty("provider", provider);
            result.test_eq(provider, hash->name(), algo);
            result.test_eq(provider, hash->name(), clone->name());

            for(size_t i = 0; i != 3; ++i) {
               hash->update(input);
               result.test_eq(provider, "hashing", hash->final(), expected);
            }

            clone->update(input);
            result.test_eq(provider, "hashing (clone)", clone->final(), expected);

            // Test to make sure clear() resets what we need it to
            hash->update("some discarded input");
            hash->clear();
            hash->update(nullptr, 0);  // this should be effectively ignored
            hash->update(input);

            result.test_eq(provider, "hashing after clear", hash->final(), expected);

            // Test that misaligned inputs work

            if(!input.empty()) {
               std::vector<uint8_t> misaligned = input;
               const size_t current_alignment = reinterpret_cast<uintptr_t>(misaligned.data()) % 16;

               const size_t bytes_to_misalign = 15 - current_alignment;

               for(size_t i = 0; i != bytes_to_misalign; ++i) {
                  misaligned.insert(misaligned.begin(), 0x23);
               }

               hash->update(&misaligned[bytes_to_misalign], input.size());
               result.test_eq(provider, "hashing misaligned data", hash->final(), expected);
            }

            if(input.size() > 5) {
               hash->update(input[0]);

               auto fork = hash->copy_state();
               // verify fork copy doesn't affect original computation
               fork->update(&input[1], input.size() - 2);

               size_t so_far = 1;
               while(so_far < input.size()) {
                  size_t take = this->rng().next_byte() % (input.size() - so_far);

                  if(input.size() - so_far == 1) {
                     take = 1;
                  }

                  hash->update(&input[so_far], take);
                  so_far += take;
               }
               result.test_eq(provider, "hashing split", hash->final(), expected);

               fork->update(&input[input.size() - 1], 1);
               result.test_eq(provider, "hashing split", fork->final(), expected);
            }

            if(hash->hash_block_size() > 0) {
               // GOST-34.11 uses 32 byte block
               result.test_gte("If hash_block_size is set, it is large", hash->hash_block_size(), 32);
            }
         }

         return result;
      }
};

BOTAN_REGISTER_SERIALIZED_SMOKE_TEST("hash", "hash_algos", Hash_Function_Tests);

class Hash_NIST_MonteCarlo_Tests final : public Text_Based_Test {
   public:
      Hash_NIST_MonteCarlo_Tests() : Text_Based_Test("hash_mc.vec", "Seed,Count,Output") {}

      std::vector<std::string> possible_providers(const std::string& algo) override {
         return provider_filter(Botan::HashFunction::providers(algo));
      }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> seed = vars.get_req_bin("Seed");
         const size_t count = vars.get_req_sz("Count");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("NIST Monte Carlo " + algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty()) {
            result.note_missing("hash " + algo);
            return result;
         }

         for(const auto& provider_ask : providers) {
            auto hash = Botan::HashFunction::create(algo, provider_ask);

            if(!hash) {
               result.test_failure(Botan::fmt("Hash {} supported by {} but not found", algo, provider_ask));
               continue;
            }

            std::vector<std::vector<uint8_t>> input;
            input.push_back(seed);
            input.push_back(seed);
            input.push_back(seed);

            std::vector<uint8_t> buf(hash->output_length());

            for(size_t j = 0; j <= count; ++j) {
               for(size_t i = 3; i != 1003; ++i) {
                  hash->update(input[0]);
                  hash->update(input[1]);
                  hash->update(input[2]);

                  hash->final(input[0].data());
                  input[0].swap(input[1]);
                  input[1].swap(input[2]);
               }

               if(j < count) {
                  input[0] = input[2];
                  input[1] = input[2];
               }
            }

            result.test_eq("Output is expected", input[2], expected);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("hash", "hash_nist_mc", Hash_NIST_MonteCarlo_Tests);

class Hash_LongRepeat_Tests final : public Text_Based_Test {
   public:
      Hash_LongRepeat_Tests() : Text_Based_Test("hash_rep.vec", "Input,TotalLength,Digest") {}

      std::vector<std::string> possible_providers(const std::string& algo) override {
         return provider_filter(Botan::HashFunction::providers(algo));
      }

      // repeating the output several times reduces buffering overhead during processing
      static std::vector<uint8_t> expand_input(const std::vector<uint8_t>& input, size_t min_len) {
         std::vector<uint8_t> output;
         output.reserve(min_len);

         while(output.size() < min_len) {
            output.insert(output.end(), input.begin(), input.end());
         }

         return output;
      }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> input = expand_input(vars.get_req_bin("Input"), 256);
         const size_t total_len = vars.get_req_sz("TotalLength");
         const std::vector<uint8_t> expected = vars.get_req_bin("Digest");

         Test::Result result("Long input " + algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(total_len > 1000000 && Test::run_long_tests() == false) {
            return result;
         }

         if(providers.empty()) {
            result.note_missing("hash " + algo);
            return result;
         }

         for(const auto& provider_ask : providers) {
            auto hash = Botan::HashFunction::create(algo, provider_ask);

            if(!hash) {
               result.test_failure(Botan::fmt("Hash {} supported by {} but not found", algo, provider_ask));
               continue;
            }

            const size_t full_inputs = total_len / input.size();
            const size_t leftover = total_len % input.size();

            for(size_t i = 0; i != full_inputs; ++i) {
               hash->update(input);
            }

            if(leftover > 0) {
               hash->update(input.data(), leftover);
            }

            std::vector<uint8_t> output(hash->output_length());
            hash->final(output.data());
            result.test_eq("Output is expected", output, expected);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("hash", "hash_rep", Hash_LongRepeat_Tests);

   #if defined(BOTAN_HAS_TRUNCATED_HASH) && defined(BOTAN_HAS_SHA2_32)

/// negative tests for Truncated_Hash, positive tests are implemented in hash/truncated.vec
Test::Result hash_truncation_negative_tests() {
   Test::Result result("hash truncation parameter validation");
   result.test_throws<Botan::Invalid_Argument>("truncation to zero",
                                               [] { Botan::HashFunction::create("Truncated(SHA-256,0)"); });
   result.test_throws<Botan::Invalid_Argument>("cannot output more bits than the underlying hash",
                                               [] { Botan::HashFunction::create("Truncated(SHA-256,257)"); });
   auto unobtainable = Botan::HashFunction::create("Truncated(NonExistentHash-256,128)");
   result.confirm("non-existent hashes are not created", unobtainable == nullptr);
   return result;
}

BOTAN_REGISTER_TEST_FN("hash", "hash_truncation", hash_truncation_negative_tests);

   #endif

}  // namespace

#endif

}  // namespace Botan_Tests
