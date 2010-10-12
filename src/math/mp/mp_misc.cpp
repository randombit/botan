/*
* MP Misc Functions
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asm.h>

namespace Botan {

extern "C" {

/*
* Core Division Operation
*/
size_t bigint_divcore(word q, word y2, word y1,
                      word x3, word x2, word x1)
   {
   // Compute (y2,y1) * q

   word y3 = 0;
   y1 = word_madd2(q, y1, &y3);
   y2 = word_madd2(q, y2, &y3);

   // Return (y3,y2,y1) >? (x3,x2,x1)

   if(y3 > x3) return 1;
   if(y3 < x3) return 0;
   if(y2 > x2) return 1;
   if(y2 < x2) return 0;
   if(y1 > x1) return 1;
   if(y1 < x1) return 0;
   return 0;
   }

/*
* Compare two MP integers
*/
s32bit bigint_cmp(const word x[], size_t x_size,
                  const word y[], size_t y_size)
   {
   if(x_size < y_size) { return (-bigint_cmp(y, y_size, x, x_size)); }

   while(x_size > y_size)
      {
      if(x[x_size-1])
         return 1;
      x_size--;
      }

   for(size_t j = x_size; j > 0; --j)
      {
      if(x[j-1] > y[j-1])
         return 1;
      if(x[j-1] < y[j-1])
         return -1;
      }

   return 0;
   }

/*
* Do a 2-word/1-word Division
*/
word bigint_divop(word n1, word n0, word d)
   {
   word high = n1 % d, quotient = 0;

   for(size_t j = 0; j != MP_WORD_BITS; ++j)
      {
      word high_top_bit = (high & MP_WORD_TOP_BIT);

      high <<= 1;
      high |= (n0 >> (MP_WORD_BITS-1-j)) & 1;
      quotient <<= 1;

      if(high_top_bit || high >= d)
         {
         high -= d;
         quotient |= 1;
         }
      }

   return quotient;
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

}
