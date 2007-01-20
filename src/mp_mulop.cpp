/*************************************************
* Multiply/Add Algorithm Source File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>

namespace Botan {

extern "C" {

/*************************************************
* Multiply/Add Words                             *
*************************************************/
word bigint_mul_add_words(word z[], const word x[], u32bit x_size, word y)
   {
   const u32bit blocks = x_size - (x_size % 8);

   word carry = 0;

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_madd3(z + j, x + j, y, carry);

   for(u32bit j = blocks; j != x_size; ++j)
      z[j] = word_madd3(x[j], y, z[j], carry, &carry);

   return carry;
   }

}

}
