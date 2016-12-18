/*
* PKCS #1 v1.5 Type 2 (encryption) padding
* (C) 1999-2007,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme_pkcs.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* PKCS1 Pad Operation
*/
secure_vector<uint8_t> EME_PKCS1v15::pad(const uint8_t in[], size_t inlen,
                                     size_t key_length,
                                     RandomNumberGenerator& rng) const
   {
   key_length /= 8;

   if(inlen > maximum_input_size(key_length * 8))
      {
      throw Invalid_Argument("PKCS1: Input is too large");
      }

   secure_vector<uint8_t> out(key_length);

   out[0] = 0x02;
   rng.randomize(out.data() + 1, (key_length - inlen - 2));

   for(size_t j = 1; j != key_length - inlen - 1; ++j)
      {
      if(out[j] == 0)
         {
         out[j] = rng.next_nonzero_byte();
         }
      }

   buffer_insert(out, key_length - inlen, in, inlen);

   return out;
   }

/*
* PKCS1 Unpad Operation
*/
secure_vector<uint8_t> EME_PKCS1v15::unpad(uint8_t& valid_mask,
                                        const uint8_t in[], size_t inlen) const
   {
   if(inlen < 2)
      {
      valid_mask = false;
      return secure_vector<uint8_t>();
      }

   CT::poison(in, inlen);

   uint8_t bad_input_m = 0;
   uint8_t seen_zero_m = 0;
   size_t delim_idx = 0;

   bad_input_m |= ~CT::is_equal<uint8_t>(in[0], 0);
   bad_input_m |= ~CT::is_equal<uint8_t>(in[1], 2);

   for(size_t i = 2; i < inlen; ++i)
      {
      const uint8_t is_zero_m = CT::is_zero<uint8_t>(in[i]);

      delim_idx += CT::select<uint8_t>(~seen_zero_m, 1, 0);

      bad_input_m |= is_zero_m & CT::expand_mask<uint8_t>(i < 10);
      seen_zero_m |= is_zero_m;
      }

   bad_input_m |= ~seen_zero_m;
   bad_input_m |= CT::is_less<size_t>(delim_idx, 8);

   CT::unpoison(in, inlen);
   CT::unpoison(bad_input_m);
   CT::unpoison(delim_idx);

   secure_vector<uint8_t> output(&in[delim_idx + 2], &in[inlen]);
   CT::cond_zero_mem(bad_input_m, output.data(), output.size());
   valid_mask = ~bad_input_m;
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
