/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>

#include <botan/entropy_src.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#include <array>

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(std::span<uint8_t> output) {
   if(this->accepts_input()) {
      constexpr auto s_hd_clk = sizeof(decltype(OS::get_high_resolution_clock()));
      constexpr auto s_sys_ts = sizeof(decltype(OS::get_system_timestamp_ns()));
      constexpr auto s_pid = sizeof(decltype(OS::get_process_id()));

      std::array<uint8_t, s_hd_clk + s_sys_ts + s_pid> additional_input = {0};
      auto s_additional_input = std::span(additional_input.begin(), additional_input.end());

      store_le(OS::get_high_resolution_clock(), s_additional_input.data());
      s_additional_input = s_additional_input.subspan(s_hd_clk);

#if defined(BOTAN_HAS_SYSTEM_RNG)
      System_RNG system_rng;
      system_rng.randomize(s_additional_input);
#else
      store_le(OS::get_system_timestamp_ns(), s_additional_input.data());
      s_additional_input = s_additional_input.subspan(s_sys_ts);

      store_le(OS::get_process_id(), s_additional_input.data());
#endif

      this->fill_bytes_with_input(output, additional_input);
   } else {
      this->fill_bytes_with_input(output, {});
   }
}

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs, size_t poll_bits, std::chrono::milliseconds poll_timeout) {
   if(this->accepts_input()) {
      return srcs.poll(*this, poll_bits, poll_timeout);
   } else {
      return 0;
   }
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
