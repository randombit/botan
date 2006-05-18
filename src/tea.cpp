/*************************************************
* TEA Source File                                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/tea.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* TEA Encryption                                 *
*************************************************/
void TEA::enc(const byte in[], byte out[]) const
   {
   u32bit left  = make_u32bit(in[0], in[1], in[2], in[3]),
          right = make_u32bit(in[4], in[5], in[6], in[7]);
   u32bit sum = 0;
   for(u32bit j = 0; j != 32; ++j)
      {
      sum   += 0x9E3779B9;
      left  += ((right << 4) + K[0]) ^ (right + sum) ^ ((right >> 5) + K[1]);
      right += ((left  << 4) + K[2]) ^ (left  + sum) ^ ((left  >> 5) + K[3]);
      }
   out[0] = get_byte(0, left);  out[1] = get_byte(1, left);
   out[2] = get_byte(2, left);  out[3] = get_byte(3, left);
   out[4] = get_byte(0, right); out[5] = get_byte(1, right);
   out[6] = get_byte(2, right); out[7] = get_byte(3, right);
   }

/*************************************************
* TEA Decryption                                 *
*************************************************/
void TEA::dec(const byte in[], byte out[]) const
   {
   u32bit left  = make_u32bit(in[0], in[1], in[2], in[3]),
          right = make_u32bit(in[4], in[5], in[6], in[7]);
   u32bit sum = 0xC6EF3720;
   for(u32bit j = 0; j != 32; ++j)
      {
      right -= ((left  << 4) + K[2]) ^ (left  + sum) ^ ((left  >> 5) + K[3]);
      left  -= ((right << 4) + K[0]) ^ (right + sum) ^ ((right >> 5) + K[1]);
      sum   -= 0x9E3779B9;
      }
   out[0] = get_byte(0, left);  out[1] = get_byte(1, left);
   out[2] = get_byte(2, left);  out[3] = get_byte(3, left);
   out[4] = get_byte(0, right); out[5] = get_byte(1, right);
   out[6] = get_byte(2, right); out[7] = get_byte(3, right);
   }

/*************************************************
* TEA Key Schedule                               *
*************************************************/
void TEA::key(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 4; ++j)
      K[j] = make_u32bit(key[4*j], key[4*j+1], key[4*j+2], key[4*j+3]);
   }

}
