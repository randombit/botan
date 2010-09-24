/*
* Montgomery Reduction
* (C) 1999-2010 Jack Lloyd
*     2006 Luca Piccarreta
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asm.h>
#include <botan/internal/mp_asmi.h>
#include <botan/mem_ops.h>

namespace Botan {

extern "C" {

/*
* Montgomery Reduction Algorithm
*/
void bigint_monty_redc(word z[], u32bit z_size,
                       word ws[],
                       const word x[], u32bit x_size,
                       word u)
   {
   const u32bit blocks_of_8 = x_size - (x_size % 8);

   for(u32bit i = 0; i != x_size; ++i)
      {
      word* z_i = z + i;

      const word y = z_i[0] * u;

      /*
      bigint_linmul3(ws, x, x_size, y);
      bigint_add2(z_i, z_size - i, ws, x_size+1);
      */
      word carry = 0;

      for(u32bit j = 0; j != blocks_of_8; j += 8)
         carry = word8_madd3(z_i + j, x + j, y, carry);

      for(u32bit j = blocks_of_8; j != x_size; ++j)
         z_i[j] = word_madd3(x[j], y, z_i[j], &carry);

      word z_sum = z_i[x_size] + carry;
      carry = (z_sum < z_i[x_size]);
      z_i[x_size] = z_sum;

      // Note: not constant time
      for(u32bit j = x_size + 1; carry && j != z_size - i; ++j)
         {
         ++z_i[j];
         carry = !z_i[j];
         }
      }

   word borrow = 0;
   for(u32bit i = 0; i != x_size; ++i)
      ws[i] = word_sub(z[x_size + i], x[i], &borrow);

   ws[x_size] = word_sub(z[x_size+x_size], 0, &borrow);

   copy_mem(ws + x_size + 1, z + x_size, x_size + 1);

   copy_mem(z, ws + borrow*(x_size+1), x_size + 1);
   clear_mem(z + x_size + 1, z_size - x_size - 1);
   }

}

}
