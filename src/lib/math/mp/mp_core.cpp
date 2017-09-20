/*
* MPI Add, Subtract, Word Multiply
* (C) 1999-2010,2016 Jack Lloyd
*     2006 Luca Piccarreta
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asmi.h>
#include <botan/internal/ct_utils.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>

namespace Botan {

/*
* If cond == 0, does nothing.
* If cond > 0, swaps x[0:size] with y[0:size]
* Runs in constant time
*/
void bigint_cnd_swap(word cnd, word x[], word y[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   for(size_t i = 0; i != size; ++i)
      {
      word a = x[i];
      word b = y[i];
      x[i] = CT::select(mask, b, a);
      y[i] = CT::select(mask, a, b);
      }
   }

/*
* If cond > 0 adds x[0:size] to y[0:size] and returns carry
* Runs in constant time
*/
word bigint_cnd_add(word cnd, word x[], const word y[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   word carry = 0;
   for(size_t i = 0; i != size; ++i)
      {
      /*
      Here we are relying on asm version of word_add being
      a single addcl or equivalent. Fix this.
      */
      const word z = word_add(x[i], y[i], &carry);
      x[i] = CT::select(mask, z, x[i]);
      }

   return carry & mask;
   }

/*
* If cond > 0 subs x[0:size] to y[0:size] and returns borrow
* Runs in constant time
*/
word bigint_cnd_sub(word cnd, word x[], const word y[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   word carry = 0;
   for(size_t i = 0; i != size; ++i)
      {
      const word z = word_sub(x[i], y[i], &carry);
      x[i] = CT::select(mask, z, x[i]);
      }

   return carry & mask;
   }

void bigint_cnd_abs(word cnd, word x[], size_t size)
   {
   const word mask = CT::expand_mask(cnd);

   word carry = mask & 1;
   for(size_t i = 0; i != size; ++i)
      {
      const word z = word_add(~x[i], 0, &carry);
      x[i] = CT::select(mask, z, x[i]);
      }
   }

/*
* Two Operand Addition, No Carry
*/
word bigint_add2_nc(word x[], size_t x_size, const word y[], size_t y_size)
   {
   word carry = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_add2(x + i, y + i, carry);

   for(size_t i = blocks; i != y_size; ++i)
      x[i] = word_add(x[i], y[i], &carry);

   for(size_t i = y_size; i != x_size; ++i)
      x[i] = word_add(x[i], 0, &carry);

   return carry;
   }

/*
* Three Operand Addition, No Carry
*/
word bigint_add3_nc(word z[], const word x[], size_t x_size,
                              const word y[], size_t y_size)
   {
   if(x_size < y_size)
      { return bigint_add3_nc(z, y, y_size, x, x_size); }

   word carry = 0;

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_add3(z + i, x + i, y + i, carry);

   for(size_t i = blocks; i != y_size; ++i)
      z[i] = word_add(x[i], y[i], &carry);

   for(size_t i = y_size; i != x_size; ++i)
      z[i] = word_add(x[i], 0, &carry);

   return carry;
   }

/*
* Two Operand Addition
*/
void bigint_add2(word x[], size_t x_size, const word y[], size_t y_size)
   {
   if(bigint_add2_nc(x, x_size, y, y_size))
      x[x_size] += 1;
   }

/*
* Three Operand Addition
*/
void bigint_add3(word z[], const word x[], size_t x_size,
                           const word y[], size_t y_size)
   {
   z[(x_size > y_size ? x_size : y_size)] +=
      bigint_add3_nc(z, x, x_size, y, y_size);
   }

/*
* Two Operand Subtraction
*/
word bigint_sub2(word x[], size_t x_size, const word y[], size_t y_size)
   {
   word borrow = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      borrow = word8_sub2(x + i, y + i, borrow);

   for(size_t i = blocks; i != y_size; ++i)
      x[i] = word_sub(x[i], y[i], &borrow);

   for(size_t i = y_size; i != x_size; ++i)
      x[i] = word_sub(x[i], 0, &borrow);

   return borrow;
   }

/*
* Two Operand Subtraction x = y - x
*/
void bigint_sub2_rev(word x[],  const word y[], size_t y_size)
   {
   word borrow = 0;

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      borrow = word8_sub2_rev(x + i, y + i, borrow);

   for(size_t i = blocks; i != y_size; ++i)
      x[i] = word_sub(y[i], x[i], &borrow);

   BOTAN_ASSERT(!borrow, "y must be greater than x");
   }

/*
* Three Operand Subtraction
*/
word bigint_sub3(word z[], const word x[], size_t x_size,
                           const word y[], size_t y_size)
   {
   word borrow = 0;

   BOTAN_ASSERT(x_size >= y_size, "Expected sizes");

   const size_t blocks = y_size - (y_size % 8);

   for(size_t i = 0; i != blocks; i += 8)
      borrow = word8_sub3(z + i, x + i, y + i, borrow);

   for(size_t i = blocks; i != y_size; ++i)
      z[i] = word_sub(x[i], y[i], &borrow);

   for(size_t i = y_size; i != x_size; ++i)
      z[i] = word_sub(x[i], 0, &borrow);

   return borrow;
   }

/*
* Two Operand Linear Multiply
*/
void bigint_linmul2(word x[], size_t x_size, word y)
   {
   const size_t blocks = x_size - (x_size % 8);

   word carry = 0;

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_linmul2(x + i, y, carry);

   for(size_t i = blocks; i != x_size; ++i)
      x[i] = word_madd2(x[i], y, &carry);

   x[x_size] = carry;
   }

/*
* Three Operand Linear Multiply
*/
void bigint_linmul3(word z[], const word x[], size_t x_size, word y)
   {
   const size_t blocks = x_size - (x_size % 8);

   word carry = 0;

   for(size_t i = 0; i != blocks; i += 8)
      carry = word8_linmul3(z + i, x + i, y, carry);

   for(size_t i = blocks; i != x_size; ++i)
      z[i] = word_madd2(x[i], y, &carry);

   z[x_size] = carry;
   }

/*
* Single Operand Left Shift
*/
void bigint_shl1(word x[], size_t x_size, size_t word_shift, size_t bit_shift)
   {
   if(word_shift)
      {
      copy_mem(x + word_shift, x, x_size);
      clear_mem(x, word_shift);
      }

   if(bit_shift)
      {
      word carry = 0;
      for(size_t j = word_shift; j != x_size + word_shift + 1; ++j)
         {
         word temp = x[j];
         x[j] = (temp << bit_shift) | carry;
         carry = (temp >> (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*
* Single Operand Right Shift
*/
void bigint_shr1(word x[], size_t x_size, size_t word_shift, size_t bit_shift)
   {
   if(x_size < word_shift)
      {
      clear_mem(x, x_size);
      return;
      }

   if(word_shift)
      {
      copy_mem(x, x + word_shift, x_size - word_shift);
      clear_mem(x + x_size - word_shift, word_shift);
      }

   if(bit_shift)
      {
      word carry = 0;

      size_t top = x_size - word_shift;

      while(top >= 4)
         {
         word w = x[top-1];
         x[top-1] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         w = x[top-2];
         x[top-2] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         w = x[top-3];
         x[top-3] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         w = x[top-4];
         x[top-4] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         top -= 4;
         }

      while(top)
         {
         word w = x[top-1];
         x[top-1] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));

         top--;
         }
      }
   }

/*
* Two Operand Left Shift
*/
void bigint_shl2(word y[], const word x[], size_t x_size,
                 size_t word_shift, size_t bit_shift)
   {
   for(size_t j = 0; j != x_size; ++j)
      y[j + word_shift] = x[j];
   if(bit_shift)
      {
      word carry = 0;
      for(size_t j = word_shift; j != x_size + word_shift + 1; ++j)
         {
         word w = y[j];
         y[j] = (w << bit_shift) | carry;
         carry = (w >> (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*
* Two Operand Right Shift
*/
void bigint_shr2(word y[], const word x[], size_t x_size,
                 size_t word_shift, size_t bit_shift)
   {
   if(x_size < word_shift) return;

   for(size_t j = 0; j != x_size - word_shift; ++j)
      y[j] = x[j + word_shift];
   if(bit_shift)
      {
      word carry = 0;
      for(size_t j = x_size - word_shift; j > 0; --j)
         {
         word w = y[j-1];
         y[j-1] = (w >> bit_shift) | carry;
         carry = (w << (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*
* Compare two MP integers
*/
int32_t bigint_cmp(const word x[], size_t x_size,
                  const word y[], size_t y_size)
   {
   if(x_size < y_size) { return (-bigint_cmp(y, y_size, x, x_size)); }

   while(x_size > y_size)
      {
      if(x[x_size-1])
         return 1;
      x_size--;
      }

   for(size_t i = x_size; i > 0; --i)
      {
      if(x[i-1] > y[i-1])
         return 1;
      if(x[i-1] < y[i-1])
         return -1;
      }

   return 0;
   }

/*
* Do a 2-word/1-word Division
*/
word bigint_divop(word n1, word n0, word d)
   {
   if(d == 0)
      throw Invalid_Argument("bigint_divop divide by zero");

#if defined(BOTAN_HAS_MP_DWORD)
   return ((static_cast<dword>(n1) << MP_WORD_BITS) | n0) / d;
#else

   word high = n1 % d, quotient = 0;

   for(size_t i = 0; i != MP_WORD_BITS; ++i)
      {
      word high_top_bit = (high & MP_WORD_TOP_BIT);

      high <<= 1;
      high |= (n0 >> (MP_WORD_BITS-1-i)) & 1;
      quotient <<= 1;

      if(high_top_bit || high >= d)
         {
         high -= d;
         quotient |= 1;
         }
      }

   return quotient;
#endif
   }

/*
* Do a 2-word/1-word Modulo
*/
word bigint_modop(word n1, word n0, word d)
   {
   word z = bigint_divop(n1, n0, d);
   word dummy = 0;
   z = word_madd2(z, d, &dummy);
   return (n0-z);
   }

}
