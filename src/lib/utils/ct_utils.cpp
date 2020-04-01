/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ct_utils.h>

namespace Botan {

namespace CT {

secure_vector<uint8_t> copy_output(CT::Mask<uint8_t> bad_input,
                                   const uint8_t input[],
                                   size_t input_length,
                                   size_t offset)
   {
   if(input_length == 0)
      return secure_vector<uint8_t>();

   /*
   * Ensure at runtime that offset <= input_length. This is an invalid input,
   * but we can't throw without using the poisoned value. Instead, if it happens,
   * set offset to be equal to the input length (so output_bytes becomes 0 and
   * the returned vector is empty)
   */
   const auto valid_offset = CT::Mask<size_t>::is_lte(offset, input_length);
   offset = valid_offset.select(offset, input_length);

   const size_t output_bytes = input_length - offset;

   secure_vector<uint8_t> output(input_length);

   /*
   Move the desired output bytes to the front using a slow (O^n)
   but constant time loop that does not leak the value of the offset
   */
   for(size_t i = 0; i != input_length; ++i)
      {
      /*
      start index from i rather than 0 since we know j must be >= i + offset
      to have any effect, and starting from i does not reveal information
      */
      for(size_t j = i; j != input_length; ++j)
         {
         const uint8_t b = input[j];
         const auto is_eq = CT::Mask<size_t>::is_equal(j, offset + i);
         output[i] |= is_eq.if_set_return(b);
         }
      }

   bad_input.if_set_zero_out(output.data(), output.size());

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

secure_vector<uint8_t> strip_leading_zeros(const uint8_t in[], size_t length)
   {
   size_t leading_zeros = 0;

   auto only_zeros = Mask<uint8_t>::set();

   for(size_t i = 0; i != length; ++i)
      {
      only_zeros &= CT::Mask<uint8_t>::is_zero(in[i]);
      leading_zeros += only_zeros.if_set_return(1);
      }

   return copy_output(CT::Mask<uint8_t>::cleared(), in, length, leading_zeros);
   }

}

}
