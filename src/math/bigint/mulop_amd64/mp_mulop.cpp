/*
* Simple O(N^2) Multiplication and Squaring
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>
#include <botan/mem_ops.h>

namespace Botan {

extern "C" {

/*
* Simple O(N^2) Multiplication
*/
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

inline word word_sqr(word x,

/*
* Simple O(N^2) Squaring

This is exactly the same algorithm as bigint_simple_mul,
however because C/C++ compilers suck at alias analysis it
is good to have the version where the compiler knows
that x == y
*/
void bigint_simple_sqr(word z[], const word x[], u32bit x_size)
   {
   clear_mem(z, 2*x_size);

   for(u32bit i = 0; i != x_size; ++i)
      {
      const word x_i = x[i];

      word carry = z[2*i];
      z[2*i] = word_madd2(x_i, x_i, z[2*i], &carry);

      for(u32bit j = i; j != x_size; ++j)
         {
         // z[i+j] = z[i+j] + 2 * x[j] * x_i + carry;

         /*
         load z[i+j] into register
         load x[j] into %hi
         mulq %[x_i] -> x[i] * x[j] -> %lo:%hi
         shlq %lo, $1

         // put carry bit (cf) from %lo into %temp
         xorl %temp
         adcq $0, %temp

         // high bit of lo now in cf
         shl %hi, $1
         // add in lowest bid from %lo
         orl %temp, %hi

         addq %[c], %[lo]
         adcq $0, %[hi]
         addq %[z_ij], %[lo]
         adcq $0, %[hi]

         */

         }

      z[x_size+i] = carry;
      }
   }

}

}
