/*
* MP Shift Algorithms
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mp_core.h>
#include <botan/mem_ops.h>

namespace Botan {

extern "C" {

/*
* Single Operand Left Shift
*/
void bigint_shl1(word x[], size_t x_size, size_t word_shift, size_t bit_shift)
   {
   if(word_shift)
      {
      for(size_t j = 1; j != x_size + 1; ++j)
         x[(x_size - j) + word_shift] = x[x_size - j];
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

}

}
