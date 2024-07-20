/*
* (C) 2015,2016,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/eme_raw.h>

#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

size_t EME_Raw::pad(std::span<uint8_t> output,
                    std::span<const uint8_t> input,
                    size_t key_length,
                    RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(rng);
   BOTAN_ASSERT_NOMSG(input.size() < maximum_input_size(8 * key_length));
   BOTAN_ASSERT_NOMSG(output.size() >= input.size());
   copy_mem(output.first(input.size()), input);
   return input.size();
}

CT::Option<size_t> EME_Raw::unpad(std::span<uint8_t> output, std::span<const uint8_t> input) const {
   BOTAN_ASSERT_NOMSG(output.size() >= input.size());

   if(input.empty()) {
      return CT::Option<size_t>(0);
   }

   const size_t leading_zeros = CT::count_leading_zero_bytes(input);
   return CT::copy_output(CT::Choice::yes(), output, input, leading_zeros);
}

size_t EME_Raw::maximum_input_size(size_t keybits) const {
   return keybits / 8;
}

}  // namespace Botan
