/*
* Lowest Level MPI Algorithms
* (C) 1999-2008 Jack Lloyd
*     2006 Luca Piccarreta
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
* Two Operand Addition, No Carry
*/
word bigint_add2_nc(word x[], u32bit x_size, const word y[], u32bit y_size)
   {
   word carry = 0;

   const u32bit blocks = y_size - (y_size % 8);

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_add2(x + j, y + j, carry);

   for(u32bit j = blocks; j != y_size; ++j)
      x[j] = word_add(x[j], y[j], &carry);

   if(!carry)
      return 0;

   for(u32bit j = y_size; j != x_size; ++j)
      if(++x[j])
         return 0;

   return 1;
   }

/*
* Three Operand Addition, No Carry
*/
word bigint_add3_nc(word z[], const word x[], u32bit x_size,
                              const word y[], u32bit y_size)
   {
   if(x_size < y_size)
      { return bigint_add3_nc(z, y, y_size, x, x_size); }

   word carry = 0;

   const u32bit blocks = y_size - (y_size % 8);

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_add3(z + j, x + j, y + j, carry);

   for(u32bit j = blocks; j != y_size; ++j)
      z[j] = word_add(x[j], y[j], &carry);

   for(u32bit j = y_size; j != x_size; ++j)
      {
      word x_j = x[j] + carry;
      if(carry && x_j)
         carry = 0;
      z[j] = x_j;
      }

   return carry;
   }

/*
* Two Operand Addition
*/
void bigint_add2(word x[], u32bit x_size, const word y[], u32bit y_size)
   {
   if(bigint_add2_nc(x, x_size, y, y_size))
      ++x[x_size];
   }

/*
* Three Operand Addition
*/
void bigint_add3(word z[], const word x[], u32bit x_size,
                           const word y[], u32bit y_size)
   {
   if(bigint_add3_nc(z, x, x_size, y, y_size))
      ++z[(x_size > y_size ? x_size : y_size)];
   }

/*
* Two Operand Subtraction
*/
void bigint_sub2(word x[], u32bit x_size, const word y[], u32bit y_size)
   {
   word carry = 0;

   const u32bit blocks = y_size - (y_size % 8);

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_sub2(x + j, y + j, carry);

   for(u32bit j = blocks; j != y_size; ++j)
      x[j] = word_sub(x[j], y[j], &carry);

   if(!carry) return;

   for(u32bit j = y_size; j != x_size; ++j)
      {
      --x[j];
      if(x[j] != MP_WORD_MAX) return;
      }
   }

/*
* Three Operand Subtraction
*/
void bigint_sub3(word z[], const word x[], u32bit x_size,
                           const word y[], u32bit y_size)
   {
   word carry = 0;

   const u32bit blocks = y_size - (y_size % 8);

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_sub3(z + j, x + j, y + j, carry);

   for(u32bit j = blocks; j != y_size; ++j)
      z[j] = word_sub(x[j], y[j], &carry);

   for(u32bit j = y_size; j != x_size; ++j)
      {
      word x_j = x[j] - carry;
      if(carry && x_j != MP_WORD_MAX)
         carry = 0;
      z[j] = x_j;
      }
   }

/*
* Two Operand Linear Multiply
*/
void bigint_linmul2(word x[], u32bit x_size, word y)
   {
   const u32bit blocks = x_size - (x_size % 8);

   word carry = 0;

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_linmul2(x + j, y, carry);

   for(u32bit j = blocks; j != x_size; ++j)
      x[j] = word_madd2(x[j], y, &carry);

   x[x_size] = carry;
   }

/*
* Three Operand Linear Multiply
*/
void bigint_linmul3(word z[], const word x[], u32bit x_size, word y)
   {
   const u32bit blocks = x_size - (x_size % 8);

   word carry = 0;

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_linmul3(z + j, x + j, y, carry);

   for(u32bit j = blocks; j != x_size; ++j)
      z[j] = word_madd2(x[j], y, &carry);

   z[x_size] = carry;
   }

}

}
