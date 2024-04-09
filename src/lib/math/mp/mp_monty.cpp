/*
* Montgomery Reduction
* (C) 1999-2011 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

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
void bigint_monty_redc_generic(word z[], size_t z_size, const word p[], size_t p_size, word p_dash, word ws[]) {
   BOTAN_ARG_CHECK(z_size >= 2 * p_size && p_size > 0, "Invalid sizes for bigint_monty_redc_generic");

   word3<word> accum;

   accum.add(z[0]);

   ws[0] = accum.monty_step(p[0], p_dash);

   for(size_t i = 1; i != p_size; ++i) {
      for(size_t j = 0; j < i; ++j) {
         accum.mul(ws[j], p[i - j]);
      }

      accum.add(z[i]);
      ws[i] = accum.monty_step(p[0], p_dash);
   }

   for(size_t i = 0; i != p_size - 1; ++i) {
      for(size_t j = i + 1; j != p_size; ++j) {
         accum.mul(ws[j], p[p_size + i - j]);
      }

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

   bigint_monty_maybe_sub(p_size, z, w1, ws, p);

   // Clear the high words that contain the original input
   clear_mem(z + p_size, z_size - p_size);
}

}  // namespace Botan
