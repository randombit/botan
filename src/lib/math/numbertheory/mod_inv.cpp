/*
* (C) 1999-2011,2016,2018,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/divide.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>

namespace Botan {

/*
Sets result to a^-1 * 2^k mod a
with n <= k <= 2n
Returns k

"The Montgomery Modular Inverse - Revisited" Çetin Koç, E. Savas
https://citeseerx.ist.psu.edu/viewdoc/citations?doi=10.1.1.75.8377

A const time implementation of this algorithm is described in
"Constant Time Modular Inversion" Joppe W. Bos
http://www.joppebos.com/files/CTInversion.pdf
*/
size_t almost_montgomery_inverse(BigInt& result,
                                 const BigInt& a,
                                 const BigInt& p)
   {
   size_t k = 0;

   BigInt u = p, v = a, r = 0, s = 1;

   while(v > 0)
      {
      if(u.is_even())
         {
         u >>= 1;
         s <<= 1;
         }
      else if(v.is_even())
         {
         v >>= 1;
         r <<= 1;
         }
      else if(u > v)
         {
         u -= v;
         u >>= 1;
         r += s;
         s <<= 1;
         }
      else
         {
         v -= u;
         v >>= 1;
         s += r;
         r <<= 1;
         }

      ++k;
      }

   if(r >= p)
      {
      r -= p;
      }

   result = p - r;

   return k;
   }

BigInt normalized_montgomery_inverse(const BigInt& a, const BigInt& p)
   {
   BigInt r;
   size_t k = almost_montgomery_inverse(r, a, p);

   for(size_t i = 0; i != k; ++i)
      {
      if(r.is_odd())
         r += p;
      r >>= 1;
      }

   return r;
   }

namespace {

BigInt inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod)
   {
   // Caller should assure these preconditions:
   BOTAN_DEBUG_ASSERT(n.is_positive());
   BOTAN_DEBUG_ASSERT(mod.is_positive());
   BOTAN_DEBUG_ASSERT(n < mod);
   BOTAN_DEBUG_ASSERT(mod >= 3 && mod.is_odd());

   /*
   This uses a modular inversion algorithm designed by Niels Möller
   and implemented in Nettle. The same algorithm was later also
   adapted to GMP in mpn_sec_invert.

   It can be easily implemented in a way that does not depend on
   secret branches or memory lookups, providing resistance against
   some forms of side channel attack.

   There is also a description of the algorithm in Appendix 5 of "Fast
   Software Polynomial Multiplication on ARM Processors using the NEON Engine"
   by Danilo Câmara, Conrado P. L. Gouvêa, Julio López, and Ricardo
   Dahab in LNCS 8182
      https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf

   Thanks to Niels for creating the algorithm, explaining some things
   about it, and the reference to the paper.
   */

   const size_t mod_words = mod.sig_words();
   BOTAN_ASSERT(mod_words > 0, "Not empty");

   secure_vector<word> tmp_mem(5*mod_words);

   word* v_w = &tmp_mem[0];
   word* u_w = &tmp_mem[1*mod_words];
   word* b_w = &tmp_mem[2*mod_words];
   word* a_w = &tmp_mem[3*mod_words];
   word* mp1o2 = &tmp_mem[4*mod_words];

   CT::poison(tmp_mem.data(), tmp_mem.size());

   copy_mem(a_w, n.data(), std::min(n.size(), mod_words));
   copy_mem(b_w, mod.data(), std::min(mod.size(), mod_words));
   u_w[0] = 1;
   // v_w = 0

   // compute (mod + 1) / 2 which [because mod is odd] is equal to
   // (mod / 2) + 1
   copy_mem(mp1o2, mod.data(), std::min(mod.size(), mod_words));
   bigint_shr1(mp1o2, mod_words, 0, 1);
   word carry = bigint_add2_nc(mp1o2, mod_words, u_w, 1);
   BOTAN_ASSERT_NOMSG(carry == 0);

   // Only n.bits() + mod.bits() iterations are required, but avoid leaking the size of n
   const size_t execs = 2 * mod.bits();

   for(size_t i = 0; i != execs; ++i)
      {
      const word odd_a = a_w[0] & 1;

      //if(odd_a) a -= b
      word underflow = bigint_cnd_sub(odd_a, a_w, b_w, mod_words);

      //if(underflow) { b -= a; a = abs(a); swap(u, v); }
      bigint_cnd_add(underflow, b_w, a_w, mod_words);
      bigint_cnd_abs(underflow, a_w, mod_words);
      bigint_cnd_swap(underflow, u_w, v_w, mod_words);

      // a >>= 1
      bigint_shr1(a_w, mod_words, 0, 1);

      //if(odd_a) u -= v;
      word borrow = bigint_cnd_sub(odd_a, u_w, v_w, mod_words);

      // if(borrow) u += p
      bigint_cnd_add(borrow, u_w, mod.data(), mod_words);

      const word odd_u = u_w[0] & 1;

      // u >>= 1
      bigint_shr1(u_w, mod_words, 0, 1);

      //if(odd_u) u += mp1o2;
      bigint_cnd_add(odd_u, u_w, mp1o2, mod_words);
      }

   auto a_is_0 = CT::Mask<word>::set();
   for(size_t i = 0; i != mod_words; ++i)
      a_is_0 &= CT::Mask<word>::is_zero(a_w[i]);

   auto b_is_1 = CT::Mask<word>::is_equal(b_w[0], 1);
   for(size_t i = 1; i != mod_words; ++i)
      b_is_1 &= CT::Mask<word>::is_zero(b_w[i]);

   BOTAN_ASSERT(a_is_0.is_set(), "A is zero");

   // if b != 1 then gcd(n,mod) > 1 and inverse does not exist
   // in which case zero out the result to indicate this
   (~b_is_1).if_set_zero_out(v_w, mod_words);

   /*
   * We've placed the result in the lowest words of the temp buffer.
   * So just clear out the other values and then give that buffer to a
   * BigInt.
   */
   clear_mem(&tmp_mem[mod_words], 4*mod_words);

   CT::unpoison(tmp_mem.data(), tmp_mem.size());

   BigInt r;
   r.swap_reg(tmp_mem);
   return r;
   }

BigInt inverse_mod_pow2(const BigInt& a1, size_t k)
   {
   /*
   * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
   * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
   */

   if(a1.is_even())
      return 0;

   BigInt a = a1;
   a.mask_bits(k);

   BigInt b = 1;
   BigInt X = 0;
   BigInt newb;

   const size_t a_words = a.sig_words();

   X.grow_to(round_up(k, BOTAN_MP_WORD_BITS) / BOTAN_MP_WORD_BITS);
   b.grow_to(a_words);

   /*
   Hide the exact value of k. k is anyway known to word length
   granularity because of the length of a, so no point in doing more
   than this.
   */
   const size_t iter = round_up(k, BOTAN_MP_WORD_BITS);

   for(size_t i = 0; i != iter; ++i)
      {
      const bool b0 = b.get_bit(0);
      X.conditionally_set_bit(i, b0);
      newb = b - a;
      b.ct_cond_assign(b0, newb);
      b >>= 1;
      }

   X.mask_bits(k);
   X.const_time_unpoison();
   return X;
   }

}

BigInt inverse_mod(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative() || n.is_negative())
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");
   if(n.is_zero() || (n.is_even() && mod.is_even()))
      return 0;

   if(mod.is_odd())
      {
      /*
      Fastpath for common case. This leaks information if n > mod
      but we don't guarantee const time behavior in that case.
      */
      if(n < mod)
         return inverse_mod_odd_modulus(n, mod);
      else
         return inverse_mod_odd_modulus(ct_modulo(n, mod), mod);
      }

   const size_t mod_lz = low_zero_bits(mod);
   BOTAN_ASSERT_NOMSG(mod_lz > 0);
   const size_t mod_bits = mod.bits();
   BOTAN_ASSERT_NOMSG(mod_bits > mod_lz);

   if(mod_lz == mod_bits - 1)
      {
      // In this case we are performing an inversion modulo 2^k
      return inverse_mod_pow2(n, mod_lz);
      }

   /*
   * In this case we are performing an inversion modulo 2^k*o for
   * some k > 1 and some odd (not necessarily prime) integer.
   * Compute the inversions modulo 2^k and modulo o, then combine them
   * using CRT, which is possible because 2^k and o are relatively prime.
   */

   const BigInt o = mod >> mod_lz;
   const BigInt n_redc = ct_modulo(n, o);
   const BigInt inv_o = inverse_mod_odd_modulus(n_redc, o);
   const BigInt inv_2k = inverse_mod_pow2(n, mod_lz);

   // No modular inverse in this case:
   if(inv_o == 0 || inv_2k == 0)
      return 0;

   const BigInt m2k = BigInt::power_of_2(mod_lz);
   // Compute the CRT parameter
   const BigInt c = inverse_mod_pow2(o, mod_lz);

   // Compute h = c*(inv_2k-inv_o) mod 2^k
   BigInt h = c * (inv_2k - inv_o);
   const bool h_neg = h.is_negative();
   h.set_sign(BigInt::Positive);
   h.mask_bits(mod_lz);
   const bool h_nonzero = h.is_nonzero();
   h.ct_cond_assign(h_nonzero && h_neg, m2k - h);

   // Return result inv_o + h * o
   h *= o;
   h += inv_o;
   return h;
   }

// Deprecated forwarding functions:
BigInt inverse_euclid(const BigInt& x, const BigInt& modulus)
   {
   return inverse_mod(x, modulus);
   }

BigInt ct_inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod)
   {
   return inverse_mod_odd_modulus(n, mod);
   }

word monty_inverse(word a)
   {
   if(a % 2 == 0)
      throw Invalid_Argument("monty_inverse only valid for odd integers");

   /*
   * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
   * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
   */

   word b = 1;
   word r = 0;

   for(size_t i = 0; i != BOTAN_MP_WORD_BITS; ++i)
      {
      const word bi = b % 2;
      r >>= 1;
      r += bi << (BOTAN_MP_WORD_BITS - 1);

      b -= a * bi;
      b >>= 1;
      }

   // Now invert in addition space
   r = (MP_WORD_MAX - r) + 1;

   return r;
   }

}
