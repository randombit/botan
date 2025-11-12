/*
* Montgomery Reduction
* (C) 1999-2011,2025 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>

#include <botan/assert.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE void mul_rev_range(word3<word>& accum, const word ws[], const word p[], size_t i) {
   /*
   Unrolled version of:

   for(size_t j = 0; j < i; ++j) {
      accum.mul(ws[j], p[i - j]);
   }
   */

   size_t j = 0;
   while(j < i) {
      const size_t remaining = i - j;

      if(remaining >= 16) {
         accum.mul(ws[j], p[remaining]);
         accum.mul(ws[j + 1], p[remaining - 1]);
         accum.mul(ws[j + 2], p[remaining - 2]);
         accum.mul(ws[j + 3], p[remaining - 3]);
         accum.mul(ws[j + 4], p[remaining - 4]);
         accum.mul(ws[j + 5], p[remaining - 5]);
         accum.mul(ws[j + 6], p[remaining - 6]);
         accum.mul(ws[j + 7], p[remaining - 7]);
         accum.mul(ws[j + 8], p[remaining - 8]);
         accum.mul(ws[j + 9], p[remaining - 9]);
         accum.mul(ws[j + 10], p[remaining - 10]);
         accum.mul(ws[j + 11], p[remaining - 11]);
         accum.mul(ws[j + 12], p[remaining - 12]);
         accum.mul(ws[j + 13], p[remaining - 13]);
         accum.mul(ws[j + 14], p[remaining - 14]);
         accum.mul(ws[j + 15], p[remaining - 15]);
         j += 16;
      } else if(remaining >= 8) {
         accum.mul(ws[j], p[remaining]);
         accum.mul(ws[j + 1], p[remaining - 1]);
         accum.mul(ws[j + 2], p[remaining - 2]);
         accum.mul(ws[j + 3], p[remaining - 3]);
         accum.mul(ws[j + 4], p[remaining - 4]);
         accum.mul(ws[j + 5], p[remaining - 5]);
         accum.mul(ws[j + 6], p[remaining - 6]);
         accum.mul(ws[j + 7], p[remaining - 7]);
         j += 8;
      } else if(remaining >= 4) {
         accum.mul(ws[j], p[remaining]);
         accum.mul(ws[j + 1], p[remaining - 1]);
         accum.mul(ws[j + 2], p[remaining - 2]);
         accum.mul(ws[j + 3], p[remaining - 3]);
         j += 4;
      } else if(remaining >= 2) {
         accum.mul(ws[j], p[remaining]);
         accum.mul(ws[j + 1], p[remaining - 1]);
         j += 2;
      } else {
         accum.mul(ws[j], p[remaining]);
         j += 1;
      }
   }
}

}  // namespace

/*
* Montgomery reduction - product scanning form
*
* Algorithm 5 from "Energy-Efficient Software Implementation of Long
* Integer Modular Arithmetic"
* (https://www.iacr.org/archive/ches2005/006.pdf)
*
* See also
*
* https://eprint.iacr.org/2013/882.pdf
* https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf
*/
void bigint_monty_redc_generic(
   word r[], const word z[], size_t z_size, const word p[], size_t p_size, word p_dash, word ws[]) {
   BOTAN_ARG_CHECK(z_size >= 2 * p_size && p_size > 0, "Invalid sizes for bigint_monty_redc_generic");

   word3<word> accum;

   accum.add(z[0]);

   ws[0] = accum.monty_step(p[0], p_dash);

   for(size_t i = 1; i != p_size; ++i) {
      mul_rev_range(accum, ws, p, i);
      accum.add(z[i]);
      ws[i] = accum.monty_step(p[0], p_dash);
   }

   for(size_t i = 0; i != p_size - 1; ++i) {
      mul_rev_range(accum, &ws[i + 1], &p[i], p_size - (i + 1));
      accum.add(z[p_size + i]);
      ws[i] = accum.extract();
   }

   accum.add(z[2 * p_size - 1]);

   ws[p_size - 1] = accum.extract();
   // w1 is the final part, which is not stored in the workspace
   const word w1 = accum.extract();

   /*
   * The result might need to be reduced mod p. To avoid a timing
   * channel, always perform the subtraction. If in the compution
   * of x - p a borrow is required then x was already < p.
   *
   * x starts at ws[0] and is p_size bytes long plus a possible high
   * digit left over in w1.
   *
   * x - p starts at z[0] and is also p_size bytes long
   *
   * If borrow was set after the subtraction, then x was already less
   * than p and the subtraction was not needed. In that case overwrite
   * z[0:p_size] with the original x in ws[0:p_size].
   *
   * We only copy out p_size in the final step because we know
   * the Montgomery result is < P
   */

   bigint_monty_maybe_sub(p_size, r, w1, ws, p);
}

}  // namespace Botan
