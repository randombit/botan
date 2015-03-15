/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pad_utils.h>
#include <botan/internal/bit_ops.h>
#include <botan/eme_raw.h>

namespace Botan {

BOTAN_REGISTER_EME_NAMED_NOARGS(EME_Raw, "Raw");

secure_vector<byte> EME_Raw::pad(const byte in[], size_t in_length,
                                 size_t key_bits,
                                 RandomNumberGenerator&) const
   {
   if(in_length > 0 && (8*(in_length - 1) + high_bit(in[0]) > key_bits))
      throw Invalid_Argument("EME_Raw: Input is too large");
   return secure_vector<byte>(in, in + in_length);
   }

secure_vector<byte> EME_Raw::unpad(const byte in[], size_t in_length,
                                   size_t) const
   {
   return secure_vector<byte>(in, in + in_length);
   }

size_t EME_Raw::maximum_input_size(size_t keybits) const
   {
   return keybits / 8;
   }
}
