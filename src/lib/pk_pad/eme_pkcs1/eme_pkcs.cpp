/*
* PKCS #1 v1.5 Type 2 (encryption) padding
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme_pkcs.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* PKCS1 Pad Operation
*/
secure_vector<byte> EME_PKCS1v15::pad(const byte in[], size_t inlen,
                                     size_t olen,
                                     RandomNumberGenerator& rng) const
   {
   olen /= 8;

   if(olen < 10)
      throw Encoding_Error("PKCS1: Output space too small");
   if(inlen > olen - 10)
      throw Encoding_Error("PKCS1: Input is too large");

   secure_vector<byte> out(olen);

   out[0] = 0x02;
   for(size_t j = 1; j != olen - inlen - 1; ++j)
      while(out[j] == 0)
         out[j] = rng.next_byte();
   buffer_insert(out, olen - inlen, in, inlen);

   return out;
   }

/*
* PKCS1 Unpad Operation
*/
secure_vector<byte> EME_PKCS1v15::unpad(const byte in[], size_t inlen,
                                        size_t key_len) const
   {
   if(inlen != key_len / 8 || inlen < 10)
      throw Decoding_Error("PKCS1::unpad");

   BOTAN_CONST_TIME_POISON(in, inlen);

   byte bad_input_m = 0;
   byte seen_zero_m = 0;
   size_t delim_idx = 0;

   bad_input_m |= ~ct_is_equal_8(in[0], 2);

   for(size_t i = 1; i != inlen; ++i)
      {
      const byte is_zero_m = ct_is_zero_8(in[i]);

      delim_idx += ct_select_mask_8(~seen_zero_m, 1, 0);

      bad_input_m |= is_zero_m & ct_expand_mask_8(i < 9);
      seen_zero_m |= is_zero_m;
      }

   bad_input_m |= ~seen_zero_m;

   BOTAN_CONST_TIME_UNPOISON(in, inlen);
   BOTAN_CONST_TIME_UNPOISON(&bad_input_m, sizeof(bad_input_m));
   BOTAN_CONST_TIME_UNPOISON(&delim_idx, sizeof(delim_idx));

   if(bad_input_m)
      throw Decoding_Error("Invalid PKCS #1 v1.5 encryption padding");

   return secure_vector<byte>(&in[delim_idx + 1], &in[inlen]);
   }

/*
* Return the max input size for a given key size
*/
size_t EME_PKCS1v15::maximum_input_size(size_t keybits) const
   {
   if(keybits / 8 > 10)
      return ((keybits / 8) - 10);
   else
      return 0;
   }

}
