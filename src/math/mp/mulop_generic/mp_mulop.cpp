/*
* Simple O(N^2) Multiplication and Squaring
* (C) 1999-2008 Jack Lloyd
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
* Simple O(N^2) Multiplication
*/
void bigint_simple_mul(word z[], const word x[], size_t x_size,
                                 const word y[], size_t y_size)
   {
   const size_t x_size_8 = x_size - (x_size % 8);

   clear_mem(z, x_size + y_size);

   for(size_t i = 0; i != y_size; ++i)
      {
      const word y_i = y[i];

      word carry = 0;

      for(size_t j = 0; j != x_size_8; j += 8)
         carry = word8_madd3(z + i + j, x + j, y_i, carry);

      for(size_t j = x_size_8; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], y_i, z[i+j], &carry);

      z[x_size+i] = carry;
      }
   }

/*
* Simple O(N^2) Squaring
*
* This is exactly the same algorithm as bigint_simple_mul, however
* because C/C++ compilers suck at alias analysis it is good to have
* the version where the compiler knows that x == y
*
* There is an O(n^1.5) squaring algorithm specified in Handbook of
* Applied Cryptography, chapter 14
*
*/
void bigint_simple_sqr(word z[], const word x[], size_t x_size)
   {
   const size_t x_size_8 = x_size - (x_size % 8);

   clear_mem(z, 2*x_size);

   for(size_t i = 0; i != x_size; ++i)
      {
      const word x_i = x[i];
      word carry = 0;

      for(size_t j = 0; j != x_size_8; j += 8)
         carry = word8_madd3(z + i + j, x + j, x_i, carry);

      for(size_t j = x_size_8; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], x_i, z[i+j], &carry);

      z[x_size+i] = carry;
      }
   }

}

}
