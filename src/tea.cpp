/*************************************************
* TEA Source File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/tea.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* TEA Encryption                                 *
*************************************************/
void TEA::enc(const byte in[], byte out[]) const
   {
   u32bit left = load_be<u32bit>(in, 0), right = load_be<u32bit>(in, 1);

   u32bit sum = 0;
   for(u32bit j = 0; j != 32; ++j)
      {
      sum   += 0x9E3779B9;
      left  += ((right << 4) + K[0]) ^ (right + sum) ^ ((right >> 5) + K[1]);
      right += ((left  << 4) + K[2]) ^ (left  + sum) ^ ((left  >> 5) + K[3]);
      }

   store_be(out, left, right);
   }

/*************************************************
* TEA Decryption                                 *
*************************************************/
void TEA::dec(const byte in[], byte out[]) const
   {
   u32bit left = load_be<u32bit>(in, 0), right = load_be<u32bit>(in, 1);

   u32bit sum = 0xC6EF3720;
   for(u32bit j = 0; j != 32; ++j)
      {
      right -= ((left  << 4) + K[2]) ^ (left  + sum) ^ ((left  >> 5) + K[3]);
      left  -= ((right << 4) + K[0]) ^ (right + sum) ^ ((right >> 5) + K[1]);
      sum   -= 0x9E3779B9;
      }

   store_be(out, left, right);
   }

/*************************************************
* TEA Key Schedule                               *
*************************************************/
void TEA::key(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 4; ++j)
      K[j] = load_be<u32bit>(key, j);
   }

}
