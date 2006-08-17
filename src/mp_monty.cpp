/*************************************************
* Montgomery Reduction Source File               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>

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
      word carry = 0;

      const u32bit blocks = x_size - (x_size % 8);

      for(u32bit k = 0; k != blocks; k += 8)
         carry = word8_madd3(z_j + k, x + k, y, carry);

      for(u32bit k = blocks; k != x_size; ++k)
         z_j[k] = word_madd3(x[k], y, z_j[k], carry, &carry);

      word carry2 = 0;
      z_j[x_size] = word_add(z_j[x_size], carry, &carry2);
      carry = carry2;

      for(u32bit k = x_size + 1; carry && k != z_size - j; ++k)
         {
         ++z_j[k];
         carry = !z_j[k];
         }
      }
   }

}

}
