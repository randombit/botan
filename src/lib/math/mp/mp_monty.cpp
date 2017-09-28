/*
* Montgomery Reduction
* (C) 1999-2011 Jack Lloyd
*     2006 Luca Piccarreta
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mp_madd.h>
#include <botan/internal/mp_asmi.h>
#include <botan/internal/ct_utils.h>
#include <botan/mem_ops.h>

namespace Botan {

/*
* Montgomery Reduction Algorithm
*/
void bigint_monty_redc(word z[],
                       const word p[], size_t p_size,
                       word p_dash, word ws[])
   {
   const size_t z_size = 2*(p_size+1);

   CT::poison(z, z_size);
   CT::poison(p, p_size);
   CT::poison(ws, 2*(p_size+1));

   const size_t blocks_of_8 = p_size - (p_size % 8);

   for(size_t i = 0; i != p_size; ++i)
      {
      word* z_i = z + i;

      const word y = z_i[0] * p_dash;

      /*
      bigint_linmul3(ws, p, p_size, y);
      bigint_add2(z_i, z_size - i, ws, p_size+1);
      */

      word carry = 0;

      for(size_t j = 0; j != blocks_of_8; j += 8)
         carry = word8_madd3(z_i + j, p + j, y, carry);

      for(size_t j = blocks_of_8; j != p_size; ++j)
         z_i[j] = word_madd3(p[j], y, z_i[j], &carry);

      word z_sum = z_i[p_size] + carry;
      carry = (z_sum < z_i[p_size]);
      z_i[p_size] = z_sum;

      for(size_t j = p_size + 1; j < z_size - i; ++j)
         {
         z_i[j] += carry;
         carry = carry & !z_i[j];
         }
      }

   /*
   * The result might need to be reduced mod p. To avoid a timing
   * channel, always perform the subtraction. If in the compution
   * of x - p a borrow is required then x was already < p.
   *
   * x - p starts at ws[0] and is p_size+1 bytes long
   * x starts at ws[p_size+1] and is also p_size+1 bytes log
   * (that's the copy_mem)
   *
   * Select which address to copy from indexing off of the final
   * borrow.
   */

   word borrow = 0;
   for(size_t i = 0; i != p_size; ++i)
      ws[i] = word_sub(z[p_size + i], p[i], &borrow);

   ws[p_size] = word_sub(z[p_size+p_size], 0, &borrow);

   copy_mem(ws + p_size + 1, z + p_size, p_size + 1);

   CT::conditional_copy_mem(borrow, z, ws + (p_size + 1), ws, (p_size + 1));
   clear_mem(z + p_size + 1, z_size - p_size - 1);

   CT::unpoison(z, z_size);
   CT::unpoison(p, p_size);
   CT::unpoison(ws, 2*(p_size+1));

   // This check comes after we've used it but that's ok here
   CT::unpoison(&borrow, 1);
   BOTAN_ASSERT(borrow == 0 || borrow == 1, "Expected borrow");
   }

void bigint_monty_mul(BigInt& z, const BigInt& x, const BigInt& y,
                      const word p[], size_t p_size, word p_dash,
                      word ws[])
   {
   bigint_mul(z, x, y, &ws[0]);

   bigint_monty_redc(z.mutable_data(),
                     p, p_size, p_dash,
                     ws);
   }

void bigint_monty_sqr(BigInt& z, const BigInt& x, const word p[],
                      size_t p_size, word p_dash, word ws[])
   {
   bigint_sqr(z.mutable_data(), z.size(), &ws[0],
              x.data(), x.size(), x.sig_words());

   bigint_monty_redc(z.mutable_data(),
                     p, p_size, p_dash,
                     ws);
   }

}
