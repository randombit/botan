/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   #include <botan/entropy_src.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#elif defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

#include <array>

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(std::span<uint8_t> output) {
   if(this->accepts_input()) {
      std::array<uint8_t, 16> additional_input = {0};

#if defined(BOTAN_HAS_SYSTEM_RNG)
      // If we have a system RNG just read 128 bits from that
      system_rng().randomize(additional_input);
      constexpr size_t written = additional_input.size();
#elif defined(BOTAN_HAS_OS_UTILS)
      // Otherwise take clock + pid
      const uint64_t clock = OS::get_high_resolution_clock();
      const uint32_t pid = OS::get_process_id();  // 0 if no PIDs on this system

      store_le(std::span{additional_input}.first<8>(), clock);
      store_le(std::span{additional_input}.subspan<8, 4>(), pid);
      const size_t written = 8 + (pid != 0) ? 4 : 0;
#else
      // Nothing to use in this case
      constexpr size_t written = 0;
#endif

      this->fill_bytes_with_input(output, std::span{additional_input}.first(written));
   } else {
      this->fill_bytes_with_input(output, {});
   }
}

size_t RandomNumberGenerator::reseed_from_sources(Entropy_Sources& srcs, size_t poll_bits) {
   if(this->accepts_input()) {
#if defined(BOTAN_HAS_ENTROPY_SOURCE)
      return srcs.poll(*this, poll_bits);
#else
      BOTAN_UNUSED(srcs, poll_bits);
#endif
   }

   return 0;
}

void RandomNumberGenerator::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits) {
   if(this->accepts_input()) {
      this->add_entropy(rng.random_vec(poll_bits / 8));
   }
}

void Null_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) {
   // throw if caller tries to obtain random bytes
   if(!output.empty()) {
      throw PRNG_Unseeded("Null_RNG called");
   }
}

}  // namespace Botan
