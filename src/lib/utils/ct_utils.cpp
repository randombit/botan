/*
* (C) 2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ct_utils.h>

#include <botan/mem_ops.h>

namespace Botan {

CT::Option<size_t> CT::copy_output(CT::Choice accept,
                                   std::span<uint8_t> output,
                                   std::span<const uint8_t> input,
                                   size_t offset) {
   // This leaks information about the input length, but this happens
   // unavoidably since we are unable to ready any bytes besides those
   // in input[0..n]
   BOTAN_ARG_CHECK(output.size() >= input.size(), "Invalid span lengths");

   /*
   * We do not poison the input here because if we did we would have
   * to unpoison it at exit. We assume instead that callers have
   * already poisoned the input and will unpoison it, and the outputs,
   * at their own time.
   */

   const size_t n = input.size();

   /*
   * Start with the input at the front of the output buffer, and zeros after it
   */
   copy_mem(output.first(n), input);
   clear_mem(output.subspan(n));

   /*
   * If the offset is greater than input length, then the arguments are
   * invalid. Ideally we would throw an exception, but that leaks
   * information about the offset. Instead treat it as if the input
   * was invalid.
   */
   accept = accept && CT::Mask<size_t>::is_lte(offset, n).as_choice();

   /*
   * If the input is invalid, then set offset == input_length
   */
   offset = CT::Mask<size_t>::from_choice(accept).select(offset, n);

   /*
   * Move the desired output bytes to the front by shifting the buffer left by
   * each power of two which is set in offset, using a constant time selection
   * so that the access pattern does not depend on offset. Zeros are shifted in
   * at the end.
   *
   * Since offset <= input_length, every bit of offset is covered. If the input
   * was invalid then offset == input_length, so every input byte is shifted
   * out and the output is all zero.
   */
   for(size_t bit = 0, shift = 1; shift <= n; ++bit, shift <<= 1) {
      const CT::Mask<uint8_t> shift_mask(CT::Mask<size_t>::expand_bit(offset, bit));

      // In increasing order, so output[i + shift] is read before it is overwritten
      for(size_t i = 0; i != n - shift; ++i) {
         output[i] = shift_mask.select(output[i + shift], output[i]);
      }
      for(size_t i = n - shift; i != n; ++i) {
         output[i] = shift_mask.if_not_set_return(output[i]);
      }
   }

   // This will always be zero if the input was invalid
   const size_t output_bytes = n - offset;

   return CT::Option<size_t>(output_bytes, accept);
}

size_t CT::count_leading_zero_bytes(std::span<const uint8_t> input) {
   size_t leading_zeros = 0;
   auto only_zeros = Mask<uint8_t>::set();
   for(const uint8_t b : input) {
      only_zeros &= CT::Mask<uint8_t>::is_zero(b);
      leading_zeros += only_zeros.if_set_return(1);
   }
   return leading_zeros;
}

}  // namespace Botan
