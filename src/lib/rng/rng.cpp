/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/buffer_stuffer.h>
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

#if defined(BOTAN_HAS_HWRNG)
   #include <botan/internal/hwrng.h>
#endif

#include <algorithm>
#include <array>

namespace Botan {

void RandomNumberGenerator::accept_seed_material(std::span<const uint8_t> input) {
   this->fill_bytes_with_input({}, input);
}

namespace {

// 22 bytes is the most HMAC_DRBG(SHA-256) can accept without needing an
// additional compression for each HMAC in update
constexpr size_t RollbackInputBytes = 22;

/*
* Fill out with values likely to be unique to this call even if the system RNG
* repeats its output after a VM rollback the guest was not informed of.
* Returns the number of bytes written.
*
* The clock and system RNG are included even if the processor RNG is used, so
* that a buggy or compromised processor RNG (eg the Zen 2 RDRAND bug which
* returned all ones) does not control the entire input.
*/
size_t rollback_unique_input(std::span<uint8_t, RollbackInputBytes> out) {
   BufferStuffer stuffer(out);

#if defined(BOTAN_HAS_OS_UTILS)
   // Uses the CPU cycle counter if available
   stuffer.append(store_le(OS::get_high_resolution_clock()));
#endif

#if defined(BOTAN_HAS_HWRNG)
   // Output of the processor RNG (RDRAND/DARN/RNDR) cannot be rolled back, but on
   // some uarchs one read costs more than everything else here, so it is only
   // used if timing has shown it to be fast
   if(const auto output = HWRNG::read_if_fast()) {
      stuffer.append(store_le(*output));
   }
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   system_rng().randomize(stuffer.next(stuffer.remaining_capacity()));
#elif defined(BOTAN_HAS_HWRNG)
   // Without a system RNG the processor RNG is the only unpredictable input, so it is used even if slow
   if(HWRNG::available()) {
      while(!stuffer.full()) {
         const auto output = HWRNG::read();
         if(!output) {
            break;
         }
         const auto bytes = store_le(*output);
         stuffer.append(std::span{bytes}.first(std::min(bytes.size(), stuffer.remaining_capacity())));
      }
   }
#endif

   return out.size() - stuffer.remaining_capacity();
}

}  // namespace

void RandomNumberGenerator::randomize_with_ts_input(std::span<uint8_t> output) {
   if(!this->accepts_input()) {
      this->fill_bytes_with_input(output, {});
      return;
   }

   // TODO(C++26): let rollback_unique_input return std::inplace_vector
   std::array<uint8_t, RollbackInputBytes> additional_input = {0};
   const size_t written = rollback_unique_input(additional_input);
   this->fill_bytes_with_input(output, std::span{additional_input}.first(written));
}

size_t RandomNumberGenerator::reseed_from_sources(Entropy_Sources& srcs, size_t poll_bits) {
   if(this->accepts_input()) {
#if defined(BOTAN_HAS_ENTROPY_SOURCE)
      Entropy_Accumulator acc(poll_bits, [this](std::span<const uint8_t> in) { this->fill_bytes_with_input({}, in); });
      srcs._gather(acc);
      return acc.bits_collected();
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
