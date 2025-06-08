/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>

#include <botan/internal/loadstor.h>

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   #include <botan/entropy_src.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

#include <array>

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(std::span<uint8_t> output) {
   if(this->accepts_input()) {
      std::array<uint8_t, 32> additional_input = {0};

#if defined(BOTAN_HAS_OS_UTILS)
      store_le(std::span{additional_input}.subspan<0, 8>(), OS::get_high_resolution_clock());
      store_le(std::span{additional_input}.subspan<8, 4>(), OS::get_process_id());
      constexpr size_t offset = 12;
#else
      constexpr size_t offset = 0;
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
      system_rng().randomize(std::span{additional_input}.subspan<offset>());
#else
      BOTAN_UNUSED(offset);
#endif

      this->fill_bytes_with_input(output, additional_input);
   } else {
      this->fill_bytes_with_input(output, {});
   }
}

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs, size_t poll_bits, std::chrono::milliseconds poll_timeout) {
   if(this->accepts_input()) {
#if defined(BOTAN_HAS_ENTROPY_SOURCE)
      return srcs.poll(*this, poll_bits, poll_timeout);
#else
      BOTAN_UNUSED(srcs, poll_bits, poll_timeout);
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
