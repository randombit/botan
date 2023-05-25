/*
* (C) 2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ct_utils.h>

namespace Botan::CT {

secure_vector<uint8_t> copy_output(CT::Mask<uint8_t> bad_input_u8,
                                   const uint8_t input[],
                                   size_t input_length,
                                   size_t offset) {
   /*
   * We do not poison the input here because if we did we would have
   * to unpoison it at exit. We assume instead that callers have
   * already poisoned the input and will unpoison it at their own
   * time.
   */
   CT::poison(&offset, sizeof(size_t));

   secure_vector<uint8_t> output(input_length);

   auto bad_input = CT::Mask<size_t>::expand(bad_input_u8);

   /*
   * If the offset is greater than input_length then the arguments are
   * invalid. Ideally we would through an exception but that leaks
   * information about the offset. Instead treat it as if the input
   * was invalid.
   */
   bad_input |= CT::Mask<size_t>::is_gt(offset, input_length);

   /*
   * If the input is invalid, then set offset == input_length as a result
   * at the end we will set output_bytes == 0 causing the final result to
   * be an empty vector.
   */
   offset = bad_input.select(input_length, offset);

   /*
   Move the desired output bytes to the front using a slow (O^n)
   but constant time loop that does not leak the value of the offset
   */
   for(size_t i = 0; i != input_length; ++i) {
      /*
      * If bad_input was set then we modified offset to equal the input_length.
      * In that case, this_loop will be greater than input_length, and so is_eq
      * mask will always be false. As a result none of the input values will be
      * written to output.
      *
      * This is ignoring the possibility of integer overflow of offset + i. But
      * for this to happen the input would have to consume nearly the entire
      * address space, and we just allocated an output buffer of equal size.
      */
      const size_t this_loop = offset + i;

      /*
      start index from i rather than 0 since we know j must be >= i + offset
      to have any effect, and starting from i does not reveal information
      */
      for(size_t j = i; j != input_length; ++j) {
         const uint8_t b = input[j];
         const auto is_eq = CT::Mask<size_t>::is_equal(j, this_loop);
         output[i] |= is_eq.if_set_return(b);
      }
   }

   const size_t output_bytes = input_length - offset;

   CT::unpoison(output.data(), output.size());
   CT::unpoison(output_bytes);

   /*
   This is potentially not const time, depending on how std::vector is
   implemented. But since we are always reducing length, it should
   just amount to setting the member var holding the length.
   */
   output.resize(output_bytes);
   return output;
}

secure_vector<uint8_t> strip_leading_zeros(const uint8_t in[], size_t length) {
   size_t leading_zeros = 0;

   auto only_zeros = Mask<uint8_t>::set();

   for(size_t i = 0; i != length; ++i) {
      only_zeros &= CT::Mask<uint8_t>::is_zero(in[i]);
      leading_zeros += only_zeros.if_set_return(1);
   }

   return copy_output(CT::Mask<uint8_t>::cleared(), in, length, leading_zeros);
}

}  // namespace Botan::CT
