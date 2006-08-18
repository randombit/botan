/*************************************************
* Montgomery Reduction Source File               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>

namespace Botan {

extern "C" word bigint_mul_add_words(word[], const word[], u32bit, word);

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

      word carry = bigint_mul_add_words(z_j, x, x_size, y);

      word z_sum = z_j[x_size] + carry;
      carry = (z_sum < z_j[x_size]);
      z_j[x_size] = z_sum;

      for(u32bit k = x_size + 1; carry && k != z_size - j; ++k)
         {
         ++z_j[k];
         carry = !z_j[k];
         }
      }
   }

}

}
