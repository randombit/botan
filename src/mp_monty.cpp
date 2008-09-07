/*************************************************
* Montgomery Reduction Source File               *
* (C) 1999-2008 Jack Lloyd                       *
*     2006 Luca Piccarreta                       *
*************************************************/

#include <botan/mp_core.h>
#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>

#include <assert.h>
#include <stdio.h>

namespace Botan {

extern "C" {

/*************************************************
* Montgomery Reduction Algorithm                 *
*************************************************/
void bigint_monty_redc(word z[], u32bit z_size,
                       const word x[], u32bit x_size, word u)
   {
   for(u32bit j = 0; j != x_size; ++j)
      {
      word* z_j = z + j;

      const word y = z_j[0] * u;

      const u32bit blocks = x_size - (x_size % 8);

      word carry = 0;

      for(u32bit i = 0; i != blocks; i += 8)
         carry = word8_madd3(z_j + i, x + i, y, carry);

      for(u32bit i = blocks; i != x_size; ++i)
         z_j[i] = word_madd3(x[i], y, z_j[i], &carry);

      word z_sum = z_j[x_size] + carry;
      carry = (z_sum < z_j[x_size]);
      z_j[x_size] = z_sum;

      for(u32bit k = x_size + 1; carry && k != z_size - j; ++k)
         {
         ++z_j[k];
         carry = !z_j[k];
         }
      }

#if 0
   if(bigint_cmp(z + x_size, x_size + 1, x, x_size) >= 0)
      bigint_sub2(z + x_size, x_size + 1, x, x_size);
#else
   /*

s32bit bigint_cmp(const word x[], u32bit x_size,
                  const word y[], u32bit y_size)
   {
   if(x_size < y_size) { return (-bigint_cmp(y, y_size, x, x_size)); }

   while(x_size > y_size)
      {
      if(x[x_size-1])
         return 1;
      x_size--;
      }
   for(u32bit j = x_size; j > 0; --j)
      {
      if(x[j-1] > y[j-1]) return 1;
      if(x[j-1] < y[j-1]) return -1;
      }
   return 0;
   }

   */

   /*

   if((x_size+1) < x_size) { return (-bigint_cmp(y, x_size, x, (x_size+1))); }

   while((x_size+1) > x_size)
      {
      if(x[(x_size+1)-1])
         return 1;
      (x_size+1)--;
      }
   for(u32bit j = (x_size+1); j > 0; --j)
      {
      if(x[j-1] > y[j-1]) return 1;
      if(x[j-1] < y[j-1]) return -1;
      }
   return 0;

   ->

   //can't happen: if((x_size+1) < x_size) { return (-bigint_cmp(y, x_size, x, (x_size+1))); }

   // always true: while((x_size+1) > x_size)
   // {
      if(x[x_size])
          return do_sub();
      //rewrite as x_size: (x_size+1)--;
      }
   for(u32bit j = x_size; j > 0; --j)
      {
      if(x[j-1] > y[j-1])
          return do_sub();
      if(x[j-1] < y[j-1])
          return;
      }
   return do_sub();

   ->

   cleanup:

   if(x[x_size])
      return do_sub();

   for(u32bit j = x_size; j > 0; --j)
      {
      if(x[j-1] > y[j-1])
          return do_sub();
      if(x[j-1] < y[j-1])
          return;
      }
   return do_sub();

   -> arg rewrite

   bigint_cmp(z + x_size, x_size + 1, x, x_size)

   x = z + x_size
   x_size = x_size + 1
   y = x
   y_size = x_size
   ^ !!!

   if(z[x_size + x_size + 1])
      return do_sub();

   for(u32bit j = x_size; j > 0; --j)
      {
      if(z[x_size+j-1] > x[j-1])
          return do_sub();
      if(z[x_size+j-1] < x[j-1])
          return;
      }
   return do_sub();

   */

   if(z[x_size + x_size])
      {
      assert(bigint_cmp(z + x_size, x_size + 1, x, x_size) > 0);
      goto do_sub;
      }

   for(u32bit j = x_size; j > 0; --j)
      {
      if(z[x_size + j - 1] > x[j-1])
         {
         assert(bigint_cmp(z + x_size, x_size + 1, x, x_size) > 0);
         goto do_sub;
         }

      if(z[x_size + j - 1] < x[j-1])
         {
         assert(bigint_cmp(z + x_size, x_size + 1, x, x_size) < 0);
         goto done;
         }
      }

   assert(bigint_cmp(z + x_size, x_size + 1, x, x_size) == 0);

do_sub:
   bigint_sub2(z + x_size, x_size + 1, x, x_size);

done:
   return;

#endif
   }

}

}
