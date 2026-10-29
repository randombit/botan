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

   /**
   * Zeroize the entire output buffer to get started
   */
   clear_mem(output);

   /*
   * If the offset is greater than input length, then the arguments are
   * invalid. Ideally we would throw an exception, but that leaks
   * information about the offset. Instead treat it as if the input
   * was invalid.
   */
   accept = accept && CT::Mask<size_t>::is_lte(offset, input.size()).as_choice();

   /*
   * If the input is invalid, then set offset == input_length
   */
   offset = CT::Mask<size_t>::from_choice(accept).select(offset, input.size());

   /*
   * Move the desired output bytes to the front using a slow (O^n)
   * but constant time loop that does not leak the value of the offset
   */
   for(size_t i = 0; i != input.size(); ++i) {
      /*
      * If bad_input was set then we modified offset to equal the input_length.
      * In that case, this_loop will be greater than input_length, and so is_eq
      * mask will always be false. As a result none of the input values will be
      * written to output.
      *
      * This is ignoring the possibility of integer overflow of offset + i. But
      * for this to happen the input would have to consume nearly the entire
      * address space.
      */
      const size_t this_loop = offset + i;

      /*
      start index from i rather than 0 since we know j must be >= i + offset
      to have any effect, and starting from i does not reveal information
      */
      for(size_t j = i; j != input.size(); ++j) {
         const uint8_t b = input[j];
         const auto is_eq = CT::Mask<size_t>::is_equal(j, this_loop);
         output[i] |= is_eq.if_set_return(b);
      }
   }

   // This will always be zero if the input was invalid
   const size_t output_bytes = input.size() - offset;

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
