/*
* CPU Jitter Random Number Generator
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/jitter_rng.h>

#include <jitterentropy.h>

namespace Botan {

struct Jitter_RNG_Internal {
      Jitter_RNG_Internal();
      ~Jitter_RNG_Internal();
      void collect_into_buffer(std::span<uint8_t> buf);

   private:
      rand_data* m_rand_data;
};

Jitter_RNG_Internal::Jitter_RNG_Internal() {
   static int result = jent_entropy_init();

   // no further details documented regarding the return value
   BOTAN_ASSERT(result == 0, "JitterRNG: initialization successful");

   constexpr unsigned int oversampling_rate = 0;  // use default oversampling
   constexpr unsigned int flags = 0;

   m_rand_data = jent_entropy_collector_alloc(oversampling_rate, flags);
   BOTAN_ASSERT_NONNULL(m_rand_data);
}

Jitter_RNG_Internal::~Jitter_RNG_Internal() {
   if(m_rand_data) {
      jent_entropy_collector_free(m_rand_data);
      m_rand_data = nullptr;
   }
}

void Jitter_RNG_Internal::collect_into_buffer(std::span<uint8_t> buf) {
   if(buf.empty()) {
      return;
   }

   BOTAN_STATE_CHECK(m_rand_data != nullptr);

   ssize_t num_bytes = jent_read_entropy_safe(&m_rand_data, reinterpret_cast<char*>(buf.data()), buf.size());
   if(num_bytes < 0) {
      const auto error_msg = [&]() -> std::string_view {
         switch(num_bytes) {
            case -1:  // should never happen because of the check above
               return "JitterRNG: Uninitilialized";
            case -2:
               return "JitterRNG: SP800-90B repetition count online health test failed";
            case -3:
               return "JitterRNG: SP800-90B adaptive proportion online health test failed";
            case -4:
               return "JitterRNG: Internal timer generator could not be initialized";
            case -5:
               return "JitterRNG: LAG predictor health test failed";
            case -6:
               return "JitterRNG: Repetitive count test (RCT) failed permanently";
            case -7:
               return "JitterRNG: Adaptive proportion test (APT) failed permanently";
            case -8:
               return "JitterRNG: LAG prediction test failed permanently";
            default:
               return "JitterRNG: Error reading entropy";
         }
      }();
      throw Internal_Error(error_msg);
   }

   // According to the docs, `jent_read_entropy` itself runs its logic as often
   // as necessary to gather the requested number of bytes,
   // so this should actually never happen.
   BOTAN_ASSERT(static_cast<size_t>(num_bytes) == buf.size(), "JitterRNG produced the expected number of bytes");
}

Jitter_RNG::Jitter_RNG() : m_jitter{std::make_unique<Jitter_RNG_Internal>()} {}

Jitter_RNG::~Jitter_RNG() = default;

void Jitter_RNG::clear() {
   m_jitter = std::make_unique<Jitter_RNG_Internal>();
}

void Jitter_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   BOTAN_UNUSED(in);

   m_jitter->collect_into_buffer(out);
}
};  // namespace Botan
