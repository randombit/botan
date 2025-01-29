/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#include <botan/rng.h>

#if defined(BOTAN_HAS_COMPRESSION)
   #include <botan/compression.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
   #include <botan/chacha_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   #include <botan/processor_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

namespace Botan_CLI {

class PerfTest_Rng final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
#if defined(BOTAN_HAS_HMAC_DRBG)
         for(std::string hash : {"SHA-256", "SHA-384", "SHA-512"}) {
            Botan::HMAC_DRBG hmac_drbg(hash);
            bench_rng(config, hmac_drbg, hmac_drbg.name());
         }
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
         // Provide a dummy seed
         Botan::ChaCha_RNG chacha_rng(Botan::secure_vector<uint8_t>(32));
         bench_rng(config, chacha_rng, "ChaCha_RNG");
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
         Botan::AutoSeeded_RNG auto_rng;
         bench_rng(config, auto_rng, "AutoSeeded_RNG (with reseed)");
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
         bench_rng(config, Botan::system_rng(), "System_RNG");
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
         if(Botan::Processor_RNG::available()) {
            Botan::Processor_RNG hwrng;
            bench_rng(config, hwrng, "Processor_RNG");
         }
#endif
         BOTAN_UNUSED(config);
      }

   private:
      void bench_rng(const PerfConfig& config, Botan::RandomNumberGenerator& rng, const std::string& rng_name) {
         for(auto buf_size : config.buffer_sizes()) {
            Botan::secure_vector<uint8_t> buffer(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

#if defined(BOTAN_HAS_SYSTEM_RNG)
            rng.reseed_from_rng(Botan::system_rng(), 256);
#endif

            auto timer = config.make_timer(rng_name, mult * buffer.size(), "generate", "", buf_size);

            const auto runtime = config.runtime();

            timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  rng.randomize(buffer.data(), buffer.size());
               }
            });

            config.record_result(*timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("RNG", PerfTest_Rng);

}  // namespace Botan_CLI
