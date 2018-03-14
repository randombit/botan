/*
* Montgomery Reduction
* (C) 1999-2011 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_madd.h>
#include <botan/internal/mp_asmi.h>
#include <botan/internal/ct_utils.h>
#include <botan/mem_ops.h>
#include <botan/exceptn.h>

namespace Botan {

/*
* Montgomery Reduction Algorithm
*/
void bigint_monty_redc(word z[],
                       const word p[], size_t p_size, word p_dash,
                       word ws[], size_t ws_size)
   {
   const size_t z_size = 2*(p_size+1);

   if(ws_size < z_size)
      throw Invalid_Argument("bigint_monty_redc workspace too small");

   CT::poison(z, z_size);
   CT::poison(p, p_size);
   CT::poison(ws, 2*(p_size+1));

   /*
   Montgomery reduction - product scanning form

   https://www.iacr.org/archive/ches2005/006.pdf
   https://eprint.iacr.org/2013/882.pdf
   https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf
   */

   word w2 = 0, w1 = 0, w0 = 0;

   w0 = z[0];

   ws[0] = w0 * p_dash;

   word3_muladd(&w2, &w1, &w0, ws[0], p[0]);

   w0 = w1;
   w1 = w2;
   w2 = 0;

   for(size_t i = 1; i != p_size; ++i)
      {
      for(size_t j = 0; j < i; ++j)
         {
         word3_muladd(&w2, &w1, &w0, ws[j], p[i-j]);
         }

      word3_add(&w2, &w1, &w0, z[i]);

      ws[i] = w0 * p_dash;

      word3_muladd(&w2, &w1, &w0, ws[i], p[0]);

      w0 = w1;
      w1 = w2;
      w2 = 0;
      }

   for(size_t i = 0; i != p_size; ++i)
      {
      for(size_t j = i + 1; j != p_size; ++j)
         {
         word3_muladd(&w2, &w1, &w0, ws[j], p[p_size + i-j]);
         }

      word3_add(&w2, &w1, &w0, z[p_size+i]);

      ws[i] = w0;
      w0 = w1;
      w1 = w2;
      w2 = 0;
      }

   word3_add(&w2, &w1, &w0, z[z_size-1]);

   ws[p_size] = w0;
   ws[p_size+1] = w1;

   /*
   * The result might need to be reduced mod p. To avoid a timing
   * channel, always perform the subtraction. If in the compution
   * of x - p a borrow is required then x was already < p.
   *
   * x starts at ws[0] and is p_size+1 bytes long.
   * x - p starts at ws[p_size+1] and is also p_size+1 bytes log
   *
   * Select which address to copy from indexing off of the final
   * borrow.
   */

   // word borrow = bigint_sub3(ws + p_size + 1, ws, p_size + 1, p, p_size);
   word borrow = 0;
   for(size_t i = 0; i != p_size; ++i)
      ws[p_size + 1 + i] = word_sub(ws[i], p[i], &borrow);
   ws[2*p_size+1] = word_sub(ws[p_size], 0, &borrow);

   CT::conditional_copy_mem(borrow, z, ws, ws + (p_size + 1), (p_size + 1));
   clear_mem(z + p_size, z_size - p_size - 2);

   CT::unpoison(z, z_size);
   CT::unpoison(p, p_size);
   CT::unpoison(ws, 2*(p_size+1));

   // This check comes after we've used it but that's ok here
   CT::unpoison(&borrow, 1);
   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow");
   }

}
