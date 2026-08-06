/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_HASH_ENGINES)

   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/hash_engine.h>

namespace Botan_CLI {

namespace {

class PerfTest_HashEngine final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const std::vector<std::string> hashes = {"SHA-256", "SHA-512", "SHAKE-256(256)"};

         const std::vector<size_t> msg_sizes = {64, 256, 1024, 16384};
         const std::vector<size_t> counts = {16, 32, 128};

         for(const auto& hash_fn : hashes) {
            std::unique_ptr<Botan::Hash_Engine> engine;

            try {
               engine = Botan::Hash_Engine::create_or_throw(hash_fn);
            } catch(Botan::Not_Implemented&) {
               continue;
            }

            const size_t out_len = engine->output_length();

            for(size_t msg_size : msg_sizes) {
               for(size_t count : counts) {
                  std::vector<uint8_t> input_buf(count * msg_size);
                  std::vector<uint8_t> output_buf(count * out_len);

                  config.rng().randomize(input_buf);

                  std::vector<std::span<const uint8_t>> input_spans(count);
                  std::vector<std::span<uint8_t>> output_spans(count);

                  for(size_t i = 0; i < count; ++i) {
                     input_spans[i] = std::span<const uint8_t>(input_buf.data() + i * msg_size, msg_size);
                     output_spans[i] = std::span<uint8_t>(output_buf.data() + i * out_len, out_len);
                  }

                  const std::string name =
                     Botan::fmt("Hash_Engine({}) n={}", hash_fn, count);

                  const uint64_t total_bytes = static_cast<uint64_t>(count) * msg_size;
                  auto timer = config.make_timer(name, total_bytes, "batch_hash", engine->provider(), msg_size);

                  timer->run_until_elapsed(config.runtime(), [&]() { engine->batch_hash(output_spans, input_spans); });

                  config.record_result(*timer);
               }
            }
         }
      }
};

}  // namespace

BOTAN_REGISTER_PERF_TEST("hash_engine", PerfTest_HashEngine);

}  // namespace Botan_CLI

#endif
