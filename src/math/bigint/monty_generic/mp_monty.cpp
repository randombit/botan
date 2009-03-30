/*
* Montgomery Reduction
* (C) 1999-2008 Jack Lloyd
*     2006 Luca Piccarreta
*
* Distributed under the terms of the Botan license
*/

#include <botan/mp_core.h>
#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>

namespace Botan {

extern "C" {

/*
* Montgomery Reduction Algorithm
*/
void bigint_monty_redc(word z[], u32bit z_size,
                       const word x[], u32bit x_size, word u)
   {
   const u32bit blocks_of_8 = x_size - (x_size % 8);

   for(u32bit i = 0; i != x_size; ++i)
      {
      word* z_i = z + i;

      const word y = z_i[0] * u;

      word carry = 0;

      for(u32bit j = 0; j != blocks_of_8; j += 8)
         carry = word8_madd3(z_i + j, x + j, y, carry);

      for(u32bit j = blocks_of_8; j != x_size; ++j)
         z_i[j] = word_madd3(x[j], y, z_i[j], &carry);

      word z_sum = z_i[x_size] + carry;
      carry = (z_sum < z_i[x_size]);
      z_i[x_size] = z_sum;

      for(u32bit j = x_size + 1; carry && j != z_size - i; ++j)
         {
         ++z_i[j];
         carry = !z_i[j];
         }
      }

   // Check if z[x_size...x_size+1] >= x[0...x_size] using bigint_cmp (inlined)
   if(!z[x_size + x_size])
      {
      for(u32bit i = x_size; i > 0; --i)
         {
         if(z[x_size + i - 1] > x[i-1])
            break;

         if(z[x_size + i - 1] < x[i-1])
            return;
         }
      }

   // If the compare above is true, subtract using bigint_sub2 (inlined)
   word carry = 0;

   for(u32bit i = 0; i != blocks_of_8; i += 8)
      carry = word8_sub2(z + x_size + i, x + i, carry);

   for(u32bit i = blocks_of_8; i != x_size; ++i)
      z[x_size + i] = word_sub(z[x_size + i], x[i], &carry);

   if(carry)
      --z[x_size+x_size];
   }

}

}
