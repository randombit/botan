/*
* MP Misc Functions
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_madd.h>

namespace Botan {

extern "C" {

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
      throw std::runtime_error("bigint_divop divide by zero");

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
