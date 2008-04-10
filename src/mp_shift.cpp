/*************************************************
* MP Shift Algorithms Source File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/mp_core.h>
#include <botan/mem_ops.h>

namespace Botan {

extern "C" {

/*************************************************
* Single Operand Left Shift                      *
*************************************************/
void bigint_shl1(word x[], u32bit x_size, u32bit word_shift, u32bit bit_shift)
   {
   if(word_shift)
      {
      for(u32bit j = 1; j != x_size + 1; ++j)
         x[(x_size - j) + word_shift] = x[x_size - j];
      clear_mem(x, word_shift);
      }

   if(bit_shift)
      {
      word carry = 0;
      for(u32bit j = word_shift; j != x_size + word_shift + 1; ++j)
         {
         word temp = x[j];
         x[j] = (temp << bit_shift) | carry;
         carry = (temp >> (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*************************************************
* Single Operand Right Shift                     *
*************************************************/
void bigint_shr1(word x[], u32bit x_size, u32bit word_shift, u32bit bit_shift)
   {
   if(x_size < word_shift)
      {
      clear_mem(x, x_size);
      return;
      }

   if(word_shift)
      {
      for(u32bit j = 0; j != x_size - word_shift; ++j)
         x[j] = x[j + word_shift];
      for(u32bit j = x_size - word_shift; j != x_size; ++j)
         x[j] = 0;
      }

   if(bit_shift)
      {
      word carry = 0;
      for(u32bit j = x_size - word_shift; j > 0; --j)
         {
         word temp = x[j-1];
         x[j-1] = (temp >> bit_shift) | carry;
         carry = (temp << (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*************************************************
* Two Operand Left Shift                         *
*************************************************/
void bigint_shl2(word y[], const word x[], u32bit x_size,
                 u32bit word_shift, u32bit bit_shift)
   {
   for(u32bit j = 0; j != x_size; ++j)
      y[j + word_shift] = x[j];
   if(bit_shift)
      {
      word carry = 0;
      for(u32bit j = word_shift; j != x_size + word_shift + 1; ++j)
         {
         word temp = y[j];
         y[j] = (temp << bit_shift) | carry;
         carry = (temp >> (MP_WORD_BITS - bit_shift));
         }
      }
   }

/*************************************************
* Two Operand Right Shift                        *
*************************************************/
void bigint_shr2(word y[], const word x[], u32bit x_size,
                 u32bit word_shift, u32bit bit_shift)
   {
   if(x_size < word_shift) return;

   for(u32bit j = 0; j != x_size - word_shift; ++j)
      y[j] = x[j + word_shift];
   if(bit_shift)
      {
      word carry = 0;
      for(u32bit j = x_size - word_shift; j > 0; --j)
         {
         word temp = y[j-1];
         y[j-1] = (temp >> bit_shift) | carry;
         carry = (temp << (MP_WORD_BITS - bit_shift));
         }
      }
   }

}

}
