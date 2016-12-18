/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme_raw.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

secure_vector<uint8_t> EME_Raw::pad(const uint8_t in[], size_t in_length,
                                 size_t,
                                 RandomNumberGenerator&) const
   {
   return secure_vector<uint8_t>(in, in + in_length);
   }

secure_vector<uint8_t> EME_Raw::unpad(uint8_t& valid_mask,
                                   const uint8_t in[], size_t in_length) const
   {
   valid_mask = 0xFF;
   return CT::strip_leading_zeros(in, in_length);
   }

size_t EME_Raw::maximum_input_size(size_t keybits) const
   {
   return keybits / 8;
   }
}
