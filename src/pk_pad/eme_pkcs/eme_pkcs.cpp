/*
* PKCS1 EME
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eme_pkcs.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* PKCS1 Pad Operation
*/
SecureVector<byte> EME_PKCS1v15::pad(const byte in[], size_t inlen,
                                     size_t olen,
                                     RandomNumberGenerator& rng) const
   {
   olen /= 8;

   if(olen < 10)
      throw Encoding_Error("PKCS1: Output space too small");
   if(inlen > olen - 10)
      throw Encoding_Error("PKCS1: Input is too large");

   SecureVector<byte> out(olen);

   out[0] = 0x02;
   for(size_t j = 1; j != olen - inlen - 1; ++j)
      while(out[j] == 0)
         out[j] = rng.next_byte();
   out.copy(olen - inlen, in, inlen);

   return out;
   }

/*
* PKCS1 Unpad Operation
*/
SecureVector<byte> EME_PKCS1v15::unpad(const byte in[], size_t inlen,
                                       size_t key_len) const
   {

   byte bad_input_m = 0;
   byte seen_zero_m = 0;
   size_t delim_idx = 0;

   bad_input_m |= ~CT::is_equal<byte>(in[0], 2);

   for(size_t i = 1; i < inlen; ++i)
      {
      const byte is_zero_m = CT::is_zero<byte>(in[i]);

      delim_idx += CT::select<byte>(~seen_zero_m, 1, 0);

      bad_input_m |= is_zero_m & CT::expand_mask<byte>(i < 9);
      seen_zero_m |= is_zero_m;
      }

   bad_input_m |= ~seen_zero_m;
   bad_input_m |= CT::is_less<size_t>(delim_idx, 8);

   SecureVector<byte> output(&in[delim_idx + 1], inlen - (delim_idx + 1));

   if(bad_input_m)
      throw Decoding_Error("EME_PKCS1v15::unpad invalid ciphertext");
   return output;
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
