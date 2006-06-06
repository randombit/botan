/*************************************************
* Lowest Level MPI Algorithms Source File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>
#include <botan/mem_ops.h>

namespace Botan {

extern "C" {

/*************************************************
* Two Operand Addition, No Carry                 *
*************************************************/
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

/*************************************************
* Three Operand Addition, No Carry               *
*************************************************/
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

/*************************************************
* Two Operand Addition                           *
*************************************************/
void bigint_add2(word x[], u32bit x_size, const word y[], u32bit y_size)
   {
   if(bigint_add2_nc(x, x_size, y, y_size))
      ++x[x_size];
   }

/*************************************************
* Three Operand Addition                         *
*************************************************/
void bigint_add3(word z[], const word x[], u32bit x_size,
                           const word y[], u32bit y_size)
   {
   if(bigint_add3_nc(z, x, x_size, y, y_size))
      ++z[(x_size > y_size ? x_size : y_size)];
   }

/*************************************************
* Two Operand Subtraction                        *
*************************************************/
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

/*************************************************
* Three Operand Subtraction                      *
*************************************************/
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

/*************************************************
* Two Operand Linear Multiply                    *
*************************************************/
void bigint_linmul2(word x[], u32bit x_size, word y)
   {
   const u32bit blocks = x_size - (x_size % 8);

   word carry = 0;

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_linmul2(x + j, y, carry);

   for(u32bit j = blocks; j != x_size; ++j)
      x[j] = word_madd2(x[j], y, carry, &carry);

   x[x_size] = carry;
   }

/*************************************************
* Three Operand Linear Multiply                  *
*************************************************/
void bigint_linmul3(word z[], const word x[], u32bit x_size, word y)
   {
   const u32bit blocks = x_size - (x_size % 8);

   word carry = 0;

   for(u32bit j = 0; j != blocks; j += 8)
      carry = word8_linmul3(z + j, x + j, y, carry);

   for(u32bit j = blocks; j != x_size; ++j)
      z[j] = word_madd2(x[j], y, carry, &carry);

   z[x_size] = carry;
   }

/*************************************************
* Simple O(N^2) Multiplication                   *
*************************************************/
void bigint_simple_mul(word z[], const word x[], u32bit x_size,
                                 const word y[], u32bit y_size)
   {
   const u32bit blocks = y_size - (y_size % 8);

   clear_mem(z, x_size + y_size);

   for(u32bit j = 0; j != x_size; ++j)
      {
      const word x_j = x[j];
      word carry = 0;

      for(u32bit k = 0; k != blocks; k += 8)
         carry = word8_madd3(z + j + k, y + k, x_j, carry);

      for(u32bit k = blocks; k != y_size; ++k)
         z[j+k] = word_madd3(x_j, y[k], z[j+k], carry, &carry);

      z[j+y_size] = carry;
      }
   }

/*************************************************
* Montgomery Reduction Algorithm                 *
*************************************************/
void montgomery_reduce(word z[], u32bit z_size,
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

   if(bigint_cmp(z + x_size, x_size + 1, x, x_size) >= 0)
      bigint_sub2(z + x_size, x_size + 1, x, x_size);
   }

}

}
