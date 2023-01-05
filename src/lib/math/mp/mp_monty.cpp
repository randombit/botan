/*
* Montgomery Reduction
* (C) 1999-2011 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/ct_utils.h>
#include <botan/mem_ops.h>
#include <botan/exceptn.h>

namespace Botan {

/*
* Montgomery reduction - product scanning form
*
* https://www.iacr.org/archive/ches2005/006.pdf
* https://eprint.iacr.org/2013/882.pdf
* https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf
*/
void bigint_monty_redc_generic(word z[], size_t z_size,
                               const word p[], size_t p_size, word p_dash,
                               word ws[])
   {
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

   word borrow = bigint_sub3(ws + p_size + 1, ws, p_size + 1, p, p_size);

   BOTAN_DEBUG_ASSERT(borrow == 0 || borrow == 1);

   CT::conditional_copy_mem(borrow, z, ws, ws + (p_size + 1), p_size);
   clear_mem(z + p_size, z_size - p_size);
   }

}
