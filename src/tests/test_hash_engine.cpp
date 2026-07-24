/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HASH_ENGINES) && defined(BOTAN_HAS_HASH)

   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/rng.h>
   #include <botan/internal/hash_engine.h>

   #include <chrono>

namespace Botan_Tests {

namespace {

class Hash_Engine_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         // Message sizes chosen to hit various padding edge cases
         const std::vector<size_t> msg_sizes = {0,   1,   7,   24,  32,  55,  56,  63,  64,  65,  111, 112,
                                                127, 128, 129, 135, 136, 137, 200, 255, 256, 257, 271, 272};

         for(const auto& hash_fn : hash_engine_algorithms()) {
            Test::Result result("Hash_Engine " + hash_fn);

            result.start_timer();

            auto engine = Botan::Hash_Engine::create_or_throw(hash_fn);
            auto ref_hash = Botan::HashFunction::create_or_throw(hash_fn);

            const size_t parallelism = engine->parallelism();
            const size_t output_length = engine->output_length();

            result.test_str_eq("name", engine->name(), hash_fn);
            result.test_str_not_empty("provider", engine->provider());
            result.test_sz_eq("output_length", output_length, ref_hash->output_length());
            result.test_sz_gte("parallelism >= 1", parallelism, 1);

            const size_t max_count = parallelism * 4;

            for(size_t count = 0; count != max_count; ++count) {
               std::vector<std::vector<uint8_t>> input_bufs(count);
               std::vector<std::vector<uint8_t>> output_bufs(count);
               std::vector<std::span<const uint8_t>> input_spans(count);
               std::vector<std::span<uint8_t>> output_spans(count);

               for(size_t i = 0; i < count; ++i) {
                  output_bufs[i].resize(output_length);
                  output_spans[i] = output_bufs[i];
               }

               for(size_t msg_len : msg_sizes) {
                  for(size_t i = 0; i < count; ++i) {
                     input_bufs[i].resize(msg_len);
                     rng().randomize(input_bufs[i]);
                     input_spans[i] = input_bufs[i];
                  }

                  engine->batch_hash(output_spans, input_spans);

                  for(size_t i = 0; i < count; ++i) {
                     auto expected = ref_hash->process<std::vector<uint8_t>>(input_spans[i]);
                     result.test_bin_eq(hash_fn, output_bufs[i], expected);
                  }
               }
            }

            result.end_timer();
            results.push_back(result);
         }

         return results;
      }

   private:
      static std::vector<std::string> hash_engine_algorithms() {
         return std::vector<std::string> {
   #if defined(BOTAN_HAS_SHA2_32)
            "SHA-256",
   #endif
   #if defined(BOTAN_HAS_SHA2_64)
               "SHA-512",
   #endif
   #if defined(BOTAN_HAS_SHAKE)
               "SHAKE-256(192)", "SHAKE-256(256)",
   #endif
   #if defined(BOTAN_HAS_SM3)
               "SM3",
   #endif
         };
      }
};

BOTAN_REGISTER_TEST("hash", "hash_engine", Hash_Engine_Tests);

}  // namespace

}  // namespace Botan_Tests

#endif
