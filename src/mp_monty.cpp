/*************************************************
* Montgomery Reduction Source File               *
* (C) 1999-2008 Jack Lloyd                       *
*     2006 Luca Piccarreta                       *
*************************************************/

#include <botan/mp_core.h>
#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>

namespace Botan {

extern "C" {

/*************************************************
* Montgomery Reduction Algorithm                 *
*************************************************/
void bigint_monty_redc(word z[], u32bit z_size,
                       const word x[], u32bit x_size, word u)
   {
   for(u32bit j = 0; j != x_size; ++j)
      {
      word* z_j = z + j;

      const word y = z_j[0] * u;

      const u32bit blocks = x_size - (x_size % 8);

      word carry = 0;

      for(u32bit i = 0; i != blocks; i += 8)
         carry = word8_madd3(z_j + i, x + i, y, carry);

      for(u32bit i = blocks; i != x_size; ++i)
         z_j[i] = word_madd3(x[i], y, z_j[i], &carry);

      word z_sum = z_j[x_size] + carry;
      carry = (z_sum < z_j[x_size]);
      z_j[x_size] = z_sum;

      for(u32bit k = x_size + 1; carry && k != z_size - j; ++k)
         {
         ++z_j[k];
         carry = !z_j[k];
         }
      }

   /* Check if z[x_size...x_size+1] >= x[0...x_size]
      This is bigint_cmp, inlined
   */
   if(!z[x_size + x_size])
      {
      for(u32bit j = x_size; j > 0; --j)
         {
         if(z[x_size + j - 1] > x[j-1])
            break;

         if(z[x_size + j - 1] < x[j-1])
            return;
         }
      }

   /* If the compare above is true, subtract using bigint_sub2 (inlined) */
   word carry = 0;
   const u32bit blocks = x_size - (x_size % 8);

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_sub2(z + x_size + j, x + j, carry);

   for(u32bit j = blocks; j != x_size; ++j)
      z[x_size + j] = word_sub(z[x_size + j], x[j], &carry);

   if(carry)
      --z[x_size+x_size];
   }

}

}
