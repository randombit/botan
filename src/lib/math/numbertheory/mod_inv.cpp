/*
* (C) 1999-2011,2016,2018,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/divide.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

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
   if(n.is_negative() || mod.is_negative())
      throw Invalid_Argument("inverse_mod_odd_modulus: arguments must be non-negative");
   if(mod < 3 || mod.is_even())
      throw Invalid_Argument("Bad modulus to inverse_mod_odd_modulus");
   if(n >= mod)
      throw Invalid_Argument("inverse_mod_odd_modulus n >= mod not supported");

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

   // todo allow this to be pre-calculated and passed in as arg
   BigInt mp1o2 = (mod + 1) >> 1;

   const size_t mod_words = mod.sig_words();
   BOTAN_ASSERT(mod_words > 0, "Not empty");

   BigInt a = n;
   BigInt b = mod;
   BigInt u = 1, v = 0;

   a.grow_to(mod_words);
   u.grow_to(mod_words);
   v.grow_to(mod_words);
   mp1o2.grow_to(mod_words);

   secure_vector<word>& a_w = a.get_word_vector();
   secure_vector<word>& b_w = b.get_word_vector();
   secure_vector<word>& u_w = u.get_word_vector();
   secure_vector<word>& v_w = v.get_word_vector();

   CT::poison(a_w.data(), a_w.size());
   CT::poison(b_w.data(), b_w.size());
   CT::poison(u_w.data(), u_w.size());
   CT::poison(v_w.data(), v_w.size());

   // Only n.bits() + mod.bits() iterations are required, but avoid leaking the size of n
   size_t bits = 2 * mod.bits();

   while(bits--)
      {
      /*
      const word odd = a.is_odd();
      a -= odd * b;
      const word underflow = a.is_negative();
      b += a * underflow;
      a.set_sign(BigInt::Positive);

      a >>= 1;

      if(underflow)
         {
         std::swap(u, v);
         }

      u -= odd * v;
      u += u.is_negative() * mod;

      const word odd_u = u.is_odd();

      u >>= 1;
      u += mp1o2 * odd_u;
      */

      const word odd_a = a_w[0] & 1;

      //if(odd_a) a -= b
      word underflow = bigint_cnd_sub(odd_a, a_w.data(), b_w.data(), mod_words);

      //if(underflow) { b -= a; a = abs(a); swap(u, v); }
      bigint_cnd_add(underflow, b_w.data(), a_w.data(), mod_words);
      bigint_cnd_abs(underflow, a_w.data(), mod_words);
      bigint_cnd_swap(underflow, u_w.data(), v_w.data(), mod_words);

      // a >>= 1
      bigint_shr1(a_w.data(), mod_words, 0, 1);

      //if(odd_a) u -= v;
      word borrow = bigint_cnd_sub(odd_a, u_w.data(), v_w.data(), mod_words);

      // if(borrow) u += p
      bigint_cnd_add(borrow, u_w.data(), mod.data(), mod_words);

      const word odd_u = u_w[0] & 1;

      // u >>= 1
      bigint_shr1(u_w.data(), mod_words, 0, 1);

      //if(odd_u) u += mp1o2;
      bigint_cnd_add(odd_u, u_w.data(), mp1o2.data(), mod_words);
      }

   CT::unpoison(a_w.data(), a_w.size());
   CT::unpoison(b_w.data(), b_w.size());
   CT::unpoison(u_w.data(), u_w.size());
   CT::unpoison(v_w.data(), v_w.size());

   BOTAN_ASSERT(a.is_zero(), "A is zero");

   if(b != 1)
      return 0;

   return v;
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

   for(size_t i = 0; i != k; ++i)
      {
      const bool b0 = b.get_bit(0);

      X.conditionally_set_bit(i, b0);
      b -= a * b0;
      b /= 2;
      }

   return X;
   }

}

BigInt inverse_mod(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative() || n.is_negative())
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");
   if(n.is_zero())
      return 0;
   if(n.is_even() && mod.is_even())
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
   const BigInt inv_o = inverse_mod_odd_modulus(ct_modulo(n, o), o);
   const BigInt inv_2k = inverse_mod_pow2(n, mod_lz);

   // No modular inverse in this case:
   if(inv_o == 0 || inv_2k == 0)
      return 0;

   // Compute the CRT parameter
   const BigInt c = inverse_mod_pow2(o, mod_lz);

   // Compute h = c*(inv_2k-inv_o) mod 2^k
   BigInt h = c * (inv_2k - inv_o);
   const bool h_neg = h.is_negative();
   h.mask_bits(mod_lz);
   h.set_sign(BigInt::Positive);
   if(h_neg && h > 0)
      h = BigInt::power_of_2(mod_lz) - h;

   // Return result inv_o + h * o
   h *= o;
   h += inv_o;
   return h;
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
