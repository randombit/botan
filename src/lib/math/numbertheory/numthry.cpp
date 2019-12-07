/*
* Number Theory Functions
* (C) 1999-2011,2016,2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/monty.h>
#include <botan/divide.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/primality.h>
#include <algorithm>

namespace Botan {

namespace {

void sub_abs(BigInt& z, const BigInt& x, const BigInt& y)
   {
   const size_t x_sw = x.sig_words();
   const size_t y_sw = y.sig_words();
   z.resize(std::max(x_sw, y_sw));

   bigint_sub_abs(z.mutable_data(),
                  x.data(), x_sw,
                  y.data(), y_sw);
   }

}

/*
* Return the number of 0 bits at the end of n
*/
size_t low_zero_bits(const BigInt& n)
   {
   size_t low_zero = 0;

   if(n.is_positive() && n.is_nonzero())
      {
      for(size_t i = 0; i != n.size(); ++i)
         {
         const word x = n.word_at(i);

         if(x)
            {
            low_zero += ctz(x);
            break;
            }
         else
            low_zero += BOTAN_MP_WORD_BITS;
         }
      }

   return low_zero;
   }

/*
* Calculate the GCD
*/
BigInt gcd(const BigInt& a, const BigInt& b)
   {
   if(a.is_zero() || b.is_zero())
      return 0;
   if(a == 1 || b == 1)
      return 1;

   BigInt f = a;
   BigInt g = b;
   f.set_sign(BigInt::Positive);
   g.set_sign(BigInt::Positive);

   const size_t common2s = std::min(low_zero_bits(f), low_zero_bits(g));

   f >>= common2s;
   g >>= common2s;

   f.ct_cond_swap(f.is_even(), g);

   int32_t delta = 1;

   const size_t loop_cnt = 4 + 3*std::max(f.bits(), g.bits());

   BigInt newg, t;
   for(size_t i = 0; i != loop_cnt; ++i)
      {
      g.shrink_to_fit();
      f.shrink_to_fit();
      sub_abs(newg, f, g);

      const bool need_swap = (g.is_odd() && delta > 0);

      // if(need_swap) delta *= -1
      delta *= CT::Mask<uint8_t>::expand(need_swap).select(0, 2) - 1;
      f.ct_cond_swap(need_swap, g);
      g.ct_cond_swap(need_swap, newg);

      delta += 1;

      t = g;
      t += f;
      g.ct_cond_assign(g.is_odd(), t);

      g >>= 1;
      }

   f <<= common2s;

   return f;
   }

/*
* Calculate the LCM
*/
BigInt lcm(const BigInt& a, const BigInt& b)
   {
   return ct_divide(a * b, gcd(a, b));
   }

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

BigInt ct_inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod)
   {
   if(n.is_negative() || mod.is_negative())
      throw Invalid_Argument("ct_inverse_mod_odd_modulus: arguments must be non-negative");
   if(mod < 3 || mod.is_even())
      throw Invalid_Argument("Bad modulus to ct_inverse_mod_odd_modulus");
   if(n >= mod)
      throw Invalid_Argument("ct_inverse_mod_odd_modulus n >= mod not supported");

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

/*
* Find the Modular Inverse
*/
BigInt inverse_mod(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative() || n.is_negative())
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");
   if(n.is_zero())
      return 0;

   if(mod.is_odd() && n < mod)
      return ct_inverse_mod_odd_modulus(n, mod);

   return inverse_euclid(n, mod);
   }

BigInt inverse_euclid(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative() || n.is_negative())
      throw Invalid_Argument("inverse_mod: arguments must be non-negative");

   if(n.is_zero() || (n.is_even() && mod.is_even()))
      return 0; // fast fail checks

   BigInt u = mod, v = n;
   BigInt A = 1, B = 0, C = 0, D = 1;
   BigInt T0, T1, T2;

   while(u.is_nonzero())
      {
      const size_t u_zero_bits = low_zero_bits(u);
      u >>= u_zero_bits;

      const size_t v_zero_bits = low_zero_bits(v);
      v >>= v_zero_bits;

      const bool u_gte_v = (u >= v);

      for(size_t i = 0; i != u_zero_bits; ++i)
         {
         const bool needs_adjust = A.is_odd() || B.is_odd();

         T0 = A + n;
         T1 = B - mod;

         A.ct_cond_assign(needs_adjust, T0);
         B.ct_cond_assign(needs_adjust, T1);

         A >>= 1;
         B >>= 1;
         }

      for(size_t i = 0; i != v_zero_bits; ++i)
         {
         const bool needs_adjust = C.is_odd() || D.is_odd();
         T0 = C + n;
         T1 = D - mod;

         C.ct_cond_assign(needs_adjust, T0);
         D.ct_cond_assign(needs_adjust, T1);

         C >>= 1;
         D >>= 1;
         }

      T0 = u - v;
      T1 = A - C;
      T2 = B - D;

      T0.cond_flip_sign(!u_gte_v);
      T1.cond_flip_sign(!u_gte_v);
      T2.cond_flip_sign(!u_gte_v);

      u.ct_cond_assign(u_gte_v, T0);
      A.ct_cond_assign(u_gte_v, T1);
      B.ct_cond_assign(u_gte_v, T2);

      v.ct_cond_assign(!u_gte_v, T0);
      C.ct_cond_assign(!u_gte_v, T1);
      D.ct_cond_assign(!u_gte_v, T2);
      }

   if(v != 1)
      return 0; // no modular inverse

   while(D.is_negative())
      D += mod;
   while(D >= mod)
      D -= mod;

   return D;
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

/*
* Modular Exponentiation
*/
BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod)
   {
   if(mod.is_negative() || mod == 1)
      {
      return 0;
      }

   if(base.is_zero() || mod.is_zero())
      {
      if(exp.is_zero())
         return 1;
      return 0;
      }

   Modular_Reducer reduce_mod(mod);

   const size_t exp_bits = exp.bits();

   if(mod.is_odd())
      {
      const size_t powm_window = 4;

      auto monty_mod = std::make_shared<Montgomery_Params>(mod, reduce_mod);
      auto powm_base_mod = monty_precompute(monty_mod, reduce_mod.reduce(base), powm_window);
      return monty_execute(*powm_base_mod, exp, exp_bits);
      }

   /*
   Support for even modulus is just a convenience and not considered
   cryptographically important, so this implementation is slow ...
   */
   BigInt accum = 1;
   BigInt g = reduce_mod.reduce(base);
   BigInt t;

   for(size_t i = 0; i != exp_bits; ++i)
      {
      t = reduce_mod.multiply(g, accum);
      g = reduce_mod.square(g);
      accum.ct_cond_assign(exp.get_bit(i), t);
      }
   return accum;
   }


BigInt is_perfect_square(const BigInt& C)
   {
   if(C < 1)
      throw Invalid_Argument("is_perfect_square requires C >= 1");
   if(C == 1)
      return 1;

   const size_t n = C.bits();
   const size_t m = (n + 1) / 2;
   const BigInt B = C + BigInt::power_of_2(m);

   BigInt X = BigInt::power_of_2(m) - 1;
   BigInt X2 = (X*X);

   for(;;)
      {
      X = (X2 + C) / (2*X);
      X2 = (X*X);

      if(X2 < B)
         break;
      }

   if(X2 == C)
      return X;
   else
      return 0;
   }

/*
* Test for primality using Miller-Rabin
*/
bool is_prime(const BigInt& n,
              RandomNumberGenerator& rng,
              size_t prob,
              bool is_random)
   {
   if(n == 2)
      return true;
   if(n <= 1 || n.is_even())
      return false;

   const size_t n_bits = n.bits();

   // Fast path testing for small numbers (<= 65521)
   if(n_bits <= 16)
      {
      const uint16_t num = static_cast<uint16_t>(n.word_at(0));

      return std::binary_search(PRIMES, PRIMES + PRIME_TABLE_SIZE, num);
      }

   Modular_Reducer mod_n(n);

   if(rng.is_seeded())
      {
      const size_t t = miller_rabin_test_iterations(n_bits, prob, is_random);

      if(is_miller_rabin_probable_prime(n, mod_n, rng, t) == false)
         return false;

      return is_lucas_probable_prime(n, mod_n);
      }
   else
      {
      return is_bailie_psw_probable_prime(n, mod_n);
      }
   }

}
