/*************************************************
* Multiply/Add Algorithm Source File             *
* (C) 1999-2008 Jack Lloyd                       *
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

   for(u32bit i = 0; i != blocks; i += 8)
      carry = word8_madd3(z + i, x + i, y, carry);

   for(u32bit i = blocks; i != x_size; ++i)
      z[i] = word_madd3(x[i], y, z[i], &carry);

   return carry;
   }

}

}
