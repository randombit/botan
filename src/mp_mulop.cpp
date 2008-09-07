/*************************************************
* Multiply/Add Algorithm Source File             *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>
#include <botan/mem_ops.h>

namespace Botan {

extern "C" {

/*************************************************
* Simple O(N^2) Multiplication                   *
*************************************************/
void bigint_simple_mul(word z[], const word x[], u32bit x_size,
                                 const word y[], u32bit y_size)
   {
   const u32bit blocks = x_size - (x_size % 8);

   clear_mem(z, x_size + y_size);

   for(u32bit i = 0; i != y_size; ++i)
      {
      word carry = 0;

      for(u32bit j = 0; j != blocks; j += 8)
         carry = word8_madd3(z + i + j, x + j, y[i], carry);

      for(u32bit j = blocks; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], y[i], z[i+j], &carry);

      z[x_size+i] = carry;
      }
   }

/*************************************************
* Simple O(N^2) Squaring                         *
*************************************************/
void bigint_simple_sqr(word z[], const word x[], u32bit x_size)
   {
   const u32bit blocks = x_size - (x_size % 8);

   clear_mem(z, 2*x_size);

   for(u32bit i = 0; i != x_size; ++i)
      {
      word carry = 0;

      for(u32bit j = 0; j != blocks; j += 8)
         carry = word8_madd3(z + i + j, x + j, x[i], carry);

      for(u32bit j = blocks; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], x[i], z[i+j], &carry);

      z[x_size+i] = carry;
      }
   }

}

}
