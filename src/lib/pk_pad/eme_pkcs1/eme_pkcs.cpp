/*
* PKCS #1 v1.5 Type 2 (encryption) padding
* (C) 1999-2007,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/eme_pkcs.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/*
* PKCS1 Pad Operation
*/
secure_vector<uint8_t> EME_PKCS1v15::pad(const uint8_t in[],
                                         size_t inlen,
                                         size_t key_length,
                                         RandomNumberGenerator& rng) const {
   key_length /= 8;

   if(inlen > maximum_input_size(key_length * 8)) {
      throw Invalid_Argument("PKCS1: Input is too large");
   }

   secure_vector<uint8_t> out(key_length);
   BufferStuffer stuffer(out);

   const size_t padding_bytes = key_length - inlen - 2;

   stuffer.append(0x02);
   for(size_t i = 0; i != padding_bytes; ++i) {
      stuffer.append(rng.next_nonzero_byte());
   }
   stuffer.append(0x00);
   stuffer.append({in, inlen});
   BOTAN_ASSERT_NOMSG(stuffer.full());

   return out;
}

/*
* PKCS1 Unpad Operation
*/
secure_vector<uint8_t> EME_PKCS1v15::unpad(uint8_t& valid_mask, const uint8_t in[], size_t inlen) const {
   /*
   * RSA decryption pads the ciphertext up to the modulus size, so this only
   * occurs with very (!) small keys, or when fuzzing.
   *
   * 11 bytes == 00,02 + 8 bytes mandatory padding + 00
   */
   if(inlen < 11) {
      valid_mask = false;
      return secure_vector<uint8_t>();
   }

   CT::poison(in, inlen);

   CT::Mask<uint8_t> bad_input_m = CT::Mask<uint8_t>::cleared();
   CT::Mask<uint8_t> seen_zero_m = CT::Mask<uint8_t>::cleared();
   size_t delim_idx = 2;  // initial 0002

   bad_input_m |= ~CT::Mask<uint8_t>::is_equal(in[0], 0);
   bad_input_m |= ~CT::Mask<uint8_t>::is_equal(in[1], 2);

   for(size_t i = 2; i < inlen; ++i) {
      const auto is_zero_m = CT::Mask<uint8_t>::is_zero(in[i]);
      delim_idx += seen_zero_m.if_not_set_return(1);
      seen_zero_m |= is_zero_m;
   }

   // no zero delim -> bad padding
   bad_input_m |= ~seen_zero_m;
   /*
   delim indicates < 8 bytes padding -> bad padding

   We require 11 here because we are counting also the 00 delim byte
   */
   bad_input_m |= CT::Mask<uint8_t>(CT::Mask<size_t>::is_lt(delim_idx, 11));

   valid_mask = (~bad_input_m).unpoisoned_value();
   auto output = CT::copy_output(bad_input_m, in, inlen, delim_idx);

   CT::unpoison(in, inlen);

   return output;
}

/*
* Return the max input size for a given key size
*/
size_t EME_PKCS1v15::maximum_input_size(size_t keybits) const {
   if(keybits / 8 > 10) {
      return ((keybits / 8) - 10);
   } else {
      return 0;
   }
}

}  // namespace Botan
