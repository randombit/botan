/*
* PKCS1 EME
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pad_utils.h>
#include <botan/eme_pkcs.h>

namespace Botan {

BOTAN_REGISTER_EME_NAMED_NOARGS(EME_PKCS1v15, "PKCS1v15");

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
   if(inlen != key_len / 8 || inlen < 10 || in[0] != 0x02)
      throw Decoding_Error("PKCS1::unpad");

   size_t separator = 0;
   for(size_t j = 0; j != inlen; ++j)
      if(in[j] == 0)
         {
         separator = j;
         break;
         }
   if(separator < 9)
      throw Decoding_Error("PKCS1::unpad");

   return secure_vector<byte>(&in[separator + 1], &in[inlen]);
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
