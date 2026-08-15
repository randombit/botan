/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HASH_ENGINES) && defined(BOTAN_HAS_HASH)

   #include <botan/hash.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/hash_engine.h>
   #include <algorithm>

namespace Botan_Tests {

namespace {

class Hash_Engine_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const auto& hash_fn : hash_engine_algorithms()) {
            Test::Result result(Botan::fmt("Hash_Engine {}", hash_fn));

            result.start_timer();

            for(const auto& provider : Botan::Hash_Engine::possible_providers(hash_fn)) {
               auto engine = Botan::Hash_Engine::create_or_null(hash_fn, {}, provider);
               auto ref_hash = Botan::HashFunction::create(hash_fn);

               if(!engine || !ref_hash) {
                  continue;
               }

               result.test_str_eq("Hash_Engine::name", engine->name(), hash_fn);
               result.test_str_eq("Hash_Engine::provider", engine->provider(), provider);

               result.test_sz_eq("output_length", engine->output_length(), ref_hash->output_length());
               result.test_sz_gte("parallelism >= 1", engine->parallelism(), 1);

               test_batch_hash(result, rng(), *engine, *ref_hash);
               test_two_part_inputs(result, rng(), *engine, *ref_hash);
               test_common_prefix(result, rng(), *ref_hash, provider);
               test_chaining_in_place(result, rng(), *engine, *ref_hash);
            }

            result.end_timer();
            results.push_back(result);
         }

         return results;
      }

   private:
      static void test_batch_hash(Test::Result& result,
                                  Botan::RandomNumberGenerator& rng,
                                  Botan::Hash_Engine& engine,
                                  Botan::HashFunction& ref_hash) {
         // Message sizes chosen to hit various padding edge cases
         const std::vector<size_t> msg_sizes = {0,   1,   7,   24,  32,  55,  56,  63,  64,  65,  111, 112,
                                                127, 128, 129, 135, 136, 137, 200, 255, 256, 257, 271, 272};

         const size_t parallelism = engine.parallelism();
         const size_t output_length = engine.output_length();

         for(const size_t count : batch_counts(parallelism)) {
            std::vector<std::vector<uint8_t>> input_bufs(count);
            std::vector<std::vector<uint8_t>> output_bufs(count);
            std::vector<std::span<const uint8_t>> input_spans(count);
            std::vector<std::span<uint8_t>> output_spans(count);

            for(size_t i = 0; i < count; ++i) {
               output_bufs[i].resize(output_length);
               output_spans[i] = output_bufs[i];
            }

            for(const size_t msg_len : msg_sizes) {
               for(size_t i = 0; i < count; ++i) {
                  input_bufs[i].resize(msg_len);
                  rng.randomize(input_bufs[i]);
                  input_spans[i] = input_bufs[i];
               }

               engine.batch_hash(output_spans, input_spans);

               for(size_t i = 0; i < count; ++i) {
                  auto expected = ref_hash.process<std::vector<uint8_t>>(input_spans[i]);
                  result.test_bin_eq("batch_hash output", output_bufs[i], expected);
               }
            }
         }
      }

      static void test_two_part_inputs(Test::Result& result,
                                       Botan::RandomNumberGenerator& rng,
                                       Botan::Hash_Engine& engine,
                                       Botan::HashFunction& ref_hash) {
         const size_t output_length = engine.output_length();
         const size_t count = engine.parallelism() + 3;

         const std::vector<size_t> part_sizes = {0, 1, 22, 32, 55, 64, 111, 137};

         std::vector<std::vector<uint8_t>> in1_bufs(count);
         std::vector<std::vector<uint8_t>> in2_bufs(count);
         std::vector<std::vector<uint8_t>> output_bufs(count);
         std::vector<std::span<const uint8_t>> in1_spans(count);
         std::vector<std::span<const uint8_t>> in2_spans(count);
         std::vector<std::span<uint8_t>> output_spans(count);

         for(size_t i = 0; i < count; ++i) {
            output_bufs[i].resize(output_length);
            output_spans[i] = output_bufs[i];
         }

         for(const size_t len1 : part_sizes) {
            for(const size_t len2 : part_sizes) {
               for(size_t i = 0; i < count; ++i) {
                  in1_bufs[i].resize(len1);
                  in2_bufs[i].resize(len2);
                  rng.randomize(in1_bufs[i]);
                  rng.randomize(in2_bufs[i]);
                  in1_spans[i] = in1_bufs[i];
                  in2_spans[i] = in2_bufs[i];
               }

               engine.batch_hash(output_spans, in1_spans, in2_spans);

               for(size_t i = 0; i < count; ++i) {
                  ref_hash.update(in1_bufs[i]);
                  ref_hash.update(in2_bufs[i]);
                  const auto expected = ref_hash.final_stdvec();
                  result.test_bin_eq("batch_hash split inputs", output_bufs[i], expected);
               }
            }
         }
      }

      void test_common_prefix(Test::Result& result,
                              Botan::RandomNumberGenerator& rng,
                              Botan::HashFunction& ref_hash,
                              std::string_view provider) {
         const std::vector<size_t> prefix_sizes = {1, 17, 32, 55, 64, 100, 128, 200};
         const std::vector<size_t> msg_sizes = {0, 22, 32, 100};

         const std::string hash_fn = ref_hash.name();

         for(const size_t prefix_len : prefix_sizes) {
            const auto prefix = rng.random_vec(prefix_len);

            auto engine = Botan::Hash_Engine::create_or_throw(hash_fn, prefix, provider);

            const size_t output_length = engine->output_length();
            const size_t count = engine->parallelism() + 3;

            std::vector<std::vector<uint8_t>> in1_bufs(count);
            std::vector<std::vector<uint8_t>> in2_bufs(count);
            std::vector<std::vector<uint8_t>> output_bufs(count);
            std::vector<std::span<const uint8_t>> in1_spans(count);
            std::vector<std::span<const uint8_t>> in2_spans(count);
            std::vector<std::span<uint8_t>> output_spans(count);

            for(size_t i = 0; i < count; ++i) {
               output_bufs[i].resize(output_length);
               output_spans[i] = output_bufs[i];
            }

            for(const size_t msg_len : msg_sizes) {
               for(size_t i = 0; i < count; ++i) {
                  in1_bufs[i].resize(msg_len);
                  rng.randomize(in1_bufs[i]);
                  in1_spans[i] = in1_bufs[i];
               }

               engine->batch_hash(output_spans, in1_spans);

               for(size_t i = 0; i < count; ++i) {
                  ref_hash.update(prefix);
                  ref_hash.update(in1_bufs[i]);
                  const auto expected = ref_hash.final_stdvec();
                  result.test_bin_eq("prefixed hash", output_bufs[i], expected);
               }
            }

            // Also check the two part input form with a prefix
            for(size_t i = 0; i < count; ++i) {
               in1_bufs[i].resize(13);
               in2_bufs[i].resize(19);
               rng.randomize(in1_bufs[i]);
               rng.randomize(in2_bufs[i]);
               in1_spans[i] = in1_bufs[i];
               in2_spans[i] = in2_bufs[i];
            }

            engine->batch_hash(output_spans, in1_spans, in2_spans);

            for(size_t i = 0; i < count; ++i) {
               ref_hash.update(prefix);
               ref_hash.update(in1_bufs[i]);
               ref_hash.update(in2_bufs[i]);
               const auto expected = ref_hash.final_stdvec();
               result.test_bin_eq("prefixed two part hash", output_bufs[i], expected);
            }
         }
      }

      void test_chaining_in_place(Test::Result& result,
                                  Botan::RandomNumberGenerator& rng,
                                  Botan::Hash_Engine& engine,
                                  Botan::HashFunction& ref_hash) {
         const size_t output_length = engine.output_length();
         const size_t count = engine.parallelism() * 2 + 1;
         const size_t steps = 7;

         std::vector<std::vector<uint8_t>> bufs(count);
         std::vector<std::span<const uint8_t>> input_spans(count);
         std::vector<std::span<uint8_t>> output_spans(count);

         for(size_t i = 0; i < count; ++i) {
            bufs[i].resize(output_length);
            rng.randomize(bufs[i]);
            input_spans[i] = bufs[i];
            output_spans[i] = bufs[i];
         }

         std::vector<std::vector<uint8_t>> expected = bufs;

         // Outputs are documented as allowed to alias the respective input,
         // as required for stepping OTS chains in place
         for(size_t step = 0; step != steps; ++step) {
            engine.batch_hash(output_spans, input_spans);
         }

         for(size_t i = 0; i < count; ++i) {
            for(size_t step = 0; step != steps; ++step) {
               expected[i] = ref_hash.process<std::vector<uint8_t>>(expected[i]);
            }
            result.test_bin_eq("chained hash", bufs[i], expected[i]);
         }
      }

      /**
      * Batch sizes exercising the empty case, partially filled batches
      * around the parallelism boundaries, and counts large enough to
      * require multiple threads or lane groups
      */
      static std::vector<size_t> batch_counts(size_t parallelism) {
         std::vector<size_t> counts;
         for(size_t i = 0; i <= std::min<size_t>(2 * parallelism, 33); ++i) {
            counts.push_back(i);
         }
         counts.insert(counts.end(),
                       {parallelism - 1,
                        parallelism,
                        parallelism + 1,
                        2 * parallelism - 1,
                        2 * parallelism,
                        2 * parallelism + 1,
                        64,
                        65,
                        128,
                        200,
                        257});

         std::sort(counts.begin(), counts.end());
         counts.erase(std::unique(counts.begin(), counts.end()), counts.end());
         return counts;
      }

      static std::vector<std::string> hash_engine_algorithms() {
         return std::vector<std::string> {
   #if defined(BOTAN_HAS_SHA2_32)
            "SHA-256",
   #endif
   #if defined(BOTAN_HAS_SHA2_32) && defined(BOTAN_HAS_TRUNCATED_HASH)
               "Truncated(SHA-256,128)",
   #endif
   #if defined(BOTAN_HAS_SHA2_64)
               "SHA-512", "SHA-384", "SHA-512-256", "Truncated(SHA-512,256)",
   #endif
   #if defined(BOTAN_HAS_SHAKE)
               "SHAKE-128(256)", "SHAKE-256(192)", "SHAKE-256(256)", "SHAKE-256(2400)",
   #endif
   #if defined(BOTAN_HAS_SHA3)
               "SHA-3(256)", "SHA-3(512)",
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
