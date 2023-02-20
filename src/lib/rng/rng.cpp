/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
#include <botan/entropy_src.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/os_utils.h>

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(std::span<uint8_t> output)
   {
   if(this->accepts_input())
      {
      /*
      Form additional input which is provided to the PRNG implementation
      to paramaterize the KDF output.
      */
      uint8_t additional_input[16] = { 0 };
      store_le(OS::get_system_timestamp_ns(), additional_input);
      store_le(OS::get_high_resolution_clock(), additional_input + 8);

      this->fill_bytes_with_input(output, additional_input);
      }
   else
      {
      this->fill_bytes_with_input(output, {});
      }
   }

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs,
                                     size_t poll_bits,
                                     std::chrono::milliseconds poll_timeout)
   {
   if(this->accepts_input())
      {
      return srcs.poll(*this, poll_bits, poll_timeout);
      }
   else
      {
      return 0;
      }
   }

void RandomNumberGenerator::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   if(this->accepts_input())
      {
      this->add_entropy(rng.random_vec(poll_bits / 8));
      }
   }

}
