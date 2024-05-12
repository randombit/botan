/*
* (C) 1999-2011,2016,2018,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

BigInt inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod) {
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
      https://inria.hal.science/hal-01506572/document

   Thanks to Niels for creating the algorithm, explaining some things
   about it, and the reference to the paper.
   */

   const size_t mod_words = mod.sig_words();
   BOTAN_ASSERT(mod_words > 0, "Not empty");

   secure_vector<word> tmp_mem(5 * mod_words);

   word* v_w = &tmp_mem[0];
   word* u_w = &tmp_mem[1 * mod_words];
   word* b_w = &tmp_mem[2 * mod_words];
   word* a_w = &tmp_mem[3 * mod_words];
   word* mp1o2 = &tmp_mem[4 * mod_words];

   CT::poison(tmp_mem.data(), tmp_mem.size());

   copy_mem(a_w, n._data(), std::min(n.size(), mod_words));
   copy_mem(b_w, mod._data(), std::min(mod.size(), mod_words));
   u_w[0] = 1;
   // v_w = 0

   // compute (mod + 1) / 2 which [because mod is odd] is equal to
   // (mod / 2) + 1
   copy_mem(mp1o2, mod._data(), std::min(mod.size(), mod_words));
   bigint_shr1(mp1o2, mod_words, 1);
   word carry = bigint_add2_nc(mp1o2, mod_words, u_w, 1);
   BOTAN_ASSERT_NOMSG(carry == 0);

   // Only n.bits() + mod.bits() iterations are required, but avoid leaking the size of n
   const size_t execs = 2 * mod.bits();

   for(size_t i = 0; i != execs; ++i) {
      const word odd_a = a_w[0] & 1;

      //if(odd_a) a -= b
      word underflow = bigint_cnd_sub(odd_a, a_w, b_w, mod_words);

      //if(underflow) { b -= a; a = abs(a); swap(u, v); }
      bigint_cnd_add(underflow, b_w, a_w, mod_words);
      bigint_cnd_abs(underflow, a_w, mod_words);
      bigint_cnd_swap(underflow, u_w, v_w, mod_words);

      // a >>= 1
      bigint_shr1(a_w, mod_words, 1);

      //if(odd_a) u -= v;
      word borrow = bigint_cnd_sub(odd_a, u_w, v_w, mod_words);

      // if(borrow) u += p
      bigint_cnd_add(borrow, u_w, mod._data(), mod_words);

      const word odd_u = u_w[0] & 1;

      // u >>= 1
      bigint_shr1(u_w, mod_words, 1);

      //if(odd_u) u += mp1o2;
      bigint_cnd_add(odd_u, u_w, mp1o2, mod_words);
   }

   auto a_is_0 = CT::Mask<word>::set();
   for(size_t i = 0; i != mod_words; ++i) {
      a_is_0 &= CT::Mask<word>::is_zero(a_w[i]);
   }

   auto b_is_1 = CT::Mask<word>::is_equal(b_w[0], 1);
   for(size_t i = 1; i != mod_words; ++i) {
      b_is_1 &= CT::Mask<word>::is_zero(b_w[i]);
   }

   BOTAN_ASSERT(a_is_0.as_bool(), "A is zero");

   // if b != 1 then gcd(n,mod) > 1 and inverse does not exist
   // in which case zero out the result to indicate this
   (~b_is_1).if_set_zero_out(v_w, mod_words);

   /*
   * We've placed the result in the lowest words of the temp buffer.
   * So just clear out the other values and then give that buffer to a
   * BigInt.
   */
   clear_mem(&tmp_mem[mod_words], 4 * mod_words);

   CT::unpoison(tmp_mem.data(), tmp_mem.size());

   BigInt r;
   r.swap_reg(tmp_mem);
   return r;
}

BigInt inverse_mod_pow2(const BigInt& a1, size_t k) {
   /*
   * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
   * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
   */

   if(a1.is_even() || k == 0) {
      return BigInt::zero();
   }
   if(k == 1) {
      return BigInt::one();
   }

   BigInt a = a1;
   a.mask_bits(k);

   BigInt b = BigInt::one();
   BigInt X = BigInt::zero();
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

   for(size_t i = 0; i != iter; ++i) {
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

}  // namespace

BigInt inverse_mod(const BigInt& n, const BigInt& mod) {
   if(mod.is_zero()) {
      throw Invalid_Argument("inverse_mod modulus cannot be zero");
   }
   if(mod.is_negative() || n.is_negative()) {
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");
   }
   if(n.is_zero() || (n.is_even() && mod.is_even())) {
      return BigInt::zero();
   }

   if(mod.is_odd()) {
      /*
      Fastpath for common case. This leaks if n is greater than mod or
      not, but we don't guarantee const time behavior in that case.
      */
      if(n < mod) {
         return inverse_mod_odd_modulus(n, mod);
      } else {
         return inverse_mod_odd_modulus(ct_modulo(n, mod), mod);
      }
   }

   // If n is even and mod is even we already returned 0
   // If n is even and mod is odd we jumped directly to odd-modulus algo
   BOTAN_DEBUG_ASSERT(n.is_odd());

   const size_t mod_lz = low_zero_bits(mod);
   BOTAN_ASSERT_NOMSG(mod_lz > 0);
   const size_t mod_bits = mod.bits();
   BOTAN_ASSERT_NOMSG(mod_bits > mod_lz);

   if(mod_lz == mod_bits - 1) {
      // In this case we are performing an inversion modulo 2^k
      return inverse_mod_pow2(n, mod_lz);
   }

   if(mod_lz == 1) {
      /*
      Inversion modulo 2*o is an easier special case of CRT

      This is exactly the main CRT flow below but taking advantage of
      the fact that any odd number ^-1 modulo 2 is 1. As a result both
      inv_2k and c can be taken to be 1, m2k is 2, and h is always
      either 0 or 1, and its value depends only on the low bit of inv_o.

      This is worth special casing because we generate RSA primes such
      that phi(n) is of this form. However this only works for keys
      that we generated in this way; pre-existing keys will typically
      fall back to the general algorithm below.
      */

      const BigInt o = mod >> 1;
      const BigInt n_redc = ct_modulo(n, o);
      const BigInt inv_o = inverse_mod_odd_modulus(n_redc, o);

      // No modular inverse in this case:
      if(inv_o == 0) {
         return BigInt::zero();
      }

      BigInt h = inv_o;
      h.ct_cond_add(!inv_o.get_bit(0), o);
      return h;
   }

   /*
   * In this case we are performing an inversion modulo 2^k*o for
   * some k >= 2 and some odd (not necessarily prime) integer.
   * Compute the inversions modulo 2^k and modulo o, then combine them
   * using CRT, which is possible because 2^k and o are relatively prime.
   */

   const BigInt o = mod >> mod_lz;
   const BigInt n_redc = ct_modulo(n, o);
   const BigInt inv_o = inverse_mod_odd_modulus(n_redc, o);
   const BigInt inv_2k = inverse_mod_pow2(n, mod_lz);

   // No modular inverse in this case:
   if(inv_o == 0 || inv_2k == 0) {
      return BigInt::zero();
   }

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

}  // namespace Botan
