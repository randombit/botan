/*
* Number Theory Functions
* (C) 1999-2011,2016,2018,2019 Jack Lloyd
* (C) 2007,2008 Falko Strenzke, FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mod_inv.h>
#include <botan/internal/monty.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/primality.h>
#include <algorithm>

namespace Botan {

/*
* Tonelli-Shanks algorithm
*/
BigInt sqrt_modulo_prime(const BigInt& a, const BigInt& p) {
   BOTAN_ARG_CHECK(p > 1, "invalid prime");
   BOTAN_ARG_CHECK(a < p, "value to solve for must be less than p");
   BOTAN_ARG_CHECK(a >= 0, "value to solve for must not be negative");

   // some very easy cases
   if(p == 2 || a <= 1) {
      return a;
   }

   BOTAN_ARG_CHECK(p.is_odd(), "invalid prime");

   if(jacobi(a, p) != 1) {  // not a quadratic residue
      return BigInt::from_s32(-1);
   }

   const Montgomery_Params monty_p(p);

   // If p == 3 (mod 4) there is a simple solution
   if(p % 4 == 3) {
      return monty_exp_vartime(monty_p, a, ((p + 1) >> 2)).value();
   }

   // Otherwise we have to use Shanks-Tonelli
   size_t s = low_zero_bits(p - 1);
   BigInt q = p >> s;

   q -= 1;
   q >>= 1;

   secure_vector<word> ws;
   const auto one = Montgomery_Int::one(monty_p);
   const Montgomery_Int a_m(monty_p, a);

   auto r = monty_exp_vartime(monty_p, a, q);
   auto n = a_m.mul(r.square(ws), ws);
   r.mul_by(a_m, ws);

   // All values here are public, so variable time comparisons are fine
   const auto is_one = [&](const Montgomery_Int& x) { return x.repr() == one.repr(); };

   if(is_one(n)) {
      return r.value();
   }

   // find random quadratic nonresidue z
   word z = 2;
   for(;;) {
      if(jacobi(BigInt::from_word(z), p) == -1) {  // found one
         break;
      }

      z += 1;  // try next z

      /*
      * The expected number of tests to find a non-residue modulo a
      * prime is 2. If we have not found one after 256 then almost
      * certainly we have been given a non-prime p.
      */
      if(z >= 256) {
         return BigInt::from_s32(-1);
      }
   }

   auto c = monty_exp_vartime(monty_p, BigInt::from_word(z), (q << 1) + 1);

   while(!n.is_zero() && !is_one(n)) {
      auto t = n;

      size_t i = 0;
      while(!is_one(t)) {
         t.square_this_n_times(ws, 1);
         ++i;

         if(i >= s) {
            return BigInt::from_s32(-1);
         }
      }

      BOTAN_ASSERT_NOMSG(s >= (i + 1));  // No underflow!
      c.square_this_n_times(ws, s - i - 1);
      r.mul_by(c, ws);
      c.square_this_n_times(ws, 1);
      n.mul_by(c, ws);

      // s decreases as the algorithm proceeds
      BOTAN_ASSERT_NOMSG(s >= i);
      s = i;
   }

   return r.value();
}

/*
* Calculate the Jacobi symbol
*
* See Algorithm 2.149 in Handbook of Applied Cryptography
*/
int32_t jacobi(BigInt a, BigInt n) {
   BOTAN_ARG_CHECK(n.is_odd() && n >= 3, "Argument n must be an odd integer >= 3");

   if(a < 0 || a >= n) {
      a %= n;
   }

   if(a == 0) {
      return 0;
   }
   if(a == 1) {
      return 1;
   }

   int32_t s = 1;

   for(;;) {
      const size_t e = low_zero_bits(a);
      a >>= e;
      const word n_mod_8 = n.word_at(0) % 8;
      const word n_mod_4 = n_mod_8 % 4;

      if(e % 2 == 1 && (n_mod_8 == 3 || n_mod_8 == 5)) {
         s = -s;
      }

      if(n_mod_4 == 3 && a % 4 == 3) {
         s = -s;
      }

      /*
      * The HAC presentation of the algorithm uses recursion, which is not
      * desirable or necessary.
      *
      * Instead we loop accumulating the product of the various jacobi()
      * subcomputations into s, until we reach algorithm termination, which
      * occurs in one of two ways.
      *
      * If a == 1 then the recursion has completed; we can return the value of s.
      *
      * Otherwise, after swapping and reducing, check for a == 0 [this value is
      * called `n1` in HAC's presentation]. This would imply that jacobi(n1,a1)
      * would have the value 0, due to Line 1 in HAC 2.149, in which case the
      * entire product is zero, and we can immediately return that result.
      */

      if(a == 1) {
         return s;
      }

      std::swap(a, n);

      BOTAN_ASSERT_NOMSG(n.is_odd());

      a %= n;

      if(a == 0) {
         return 0;
      }
   }
}

/*
* Square a BigInt
*/
BigInt square(const BigInt& x) {
   BigInt z = x;
   secure_vector<word> ws;
   z.square(ws);
   return z;
}

/*
* Return the number of 0 bits at the end of n
*/
size_t low_zero_bits(const BigInt& n) {
   size_t low_zero = 0;

   auto seen_nonempty_word = CT::Mask<word>::cleared();

   for(size_t i = 0; i != n.size(); ++i) {
      const word x = n.word_at(i);

      // ctz(0) will return sizeof(word)
      const size_t tz_x = ctz(x);

      // if x > 0 we want to count tz_x in total but not any
      // further words, so set the mask after the addition
      low_zero += seen_nonempty_word.if_not_set_return(tz_x);

      seen_nonempty_word |= CT::Mask<word>::expand(x);
   }

   // if we saw no words with x > 0 then n == 0 and the value we have
   // computed is meaningless. Instead return BigInt::zero() in that case.
   return static_cast<size_t>(seen_nonempty_word.if_set_return(low_zero));
}

/*
* Calculate the GCD in constant time
*/
BigInt gcd(const BigInt& a, const BigInt& b) {
   if(a.is_zero()) {
      return abs(b);
   }
   if(b.is_zero()) {
      return abs(a);
   }

   const size_t sz = std::max(a.sig_words(), b.sig_words());
   auto u = BigInt::with_capacity(sz);
   auto v = BigInt::with_capacity(sz);
   u += a;
   v += b;

   CT::poison_all(u, v);

   u.set_sign(BigInt::Positive);
   v.set_sign(BigInt::Positive);

   // In the worst case we have two fully populated big ints. After right
   // shifting so many times, we'll have reached the result for sure.
   const size_t loop_cnt = u.bits() + v.bits();

   // This temporary is big enough to hold all intermediate results of the
   // algorithm. No reallocation will happen during the loop.
   // Note however, that `ct_cond_assign()` will invalidate the 'sig_words'
   // cache, which _does not_ shrink the capacity of the underlying buffer.
   auto tmp = BigInt::with_capacity(sz);
   secure_vector<word> ws(sz * 2);
   size_t factors_of_two = 0;
   for(size_t i = 0; i != loop_cnt; ++i) {
      const auto both_odd = CT::Mask<word>::expand_bool(u.is_odd()) & CT::Mask<word>::expand_bool(v.is_odd());

      // Subtract the smaller from the larger if both are odd
      const auto u_gt_v = CT::Mask<word>::expand_bool(bigint_cmp(u._data(), u.size(), v._data(), v.size()) > 0);
      bigint_sub_abs(tmp.mutable_data(), u._data(), v._data(), sz, ws.data());
      u.ct_cond_assign((u_gt_v & both_odd).as_bool(), tmp);
      v.ct_cond_assign((~u_gt_v & both_odd).as_bool(), tmp);

      const auto u_is_even = CT::Mask<word>::expand_bool(u.is_even());
      const auto v_is_even = CT::Mask<word>::expand_bool(v.is_even());
      BOTAN_DEBUG_ASSERT((u_is_even | v_is_even).as_bool());

      // When both are even, we're going to eliminate a factor of 2.
      // We have to reapply this factor to the final result.
      factors_of_two += (u_is_even & v_is_even).if_set_return(1);

      // remove one factor of 2, if u is even
      bigint_shr2(tmp.mutable_data(), sz, u._data(), sz, 1);
      u.ct_cond_assign(u_is_even.as_bool(), tmp);

      // remove one factor of 2, if v is even
      bigint_shr2(tmp.mutable_data(), sz, v._data(), sz, 1);
      v.ct_cond_assign(v_is_even.as_bool(), tmp);
   }

   // The GCD (without factors of two) is either in u or v, the other one is
   // zero. The non-zero variable _must_ be odd, because all factors of two were
   // removed in the loop iterations above.
   BOTAN_DEBUG_ASSERT(u.is_zero() || v.is_zero());
   BOTAN_DEBUG_ASSERT(u.is_odd() || v.is_odd());

   // make sure that the GCD (without factors of two) is in u
   u.ct_cond_assign(u.is_even() /* .is_zero() would not be constant time */, v);

   // re-apply the factors of two
   u.ct_shift_left(factors_of_two);

   CT::unpoison_all(u, v);

   return u;
}

/*
* Calculate the LCM
*/
BigInt lcm(const BigInt& a, const BigInt& b) {
   if(a == b) {
      return a;
   }

   auto ab = a * b;
   ab.set_sign(BigInt::Positive);  // ignore the signs of a & b
   const auto g = gcd(a, b);
   return ct_divide(ab, g);
}

namespace {

/*
* Compute b^e mod 2^k, for b >= 0, using a constant time square and multiply ladder
*/
BigInt power_mod_pow2(const BigInt& b, const BigInt& e, size_t e_bits, size_t k) {
   constexpr size_t WB = WordInfo<word>::bits;
   const size_t k_words = (k + WB - 1) / WB;
   const word top_mask = WordInfo<word>::max >> (k_words * WB - k);

   secure_vector<word> g(k_words);
   copy_mem(g.data(), b._data(), std::min(k_words, b.size()));
   g[k_words - 1] &= top_mask;

   secure_vector<word> accum(k_words);
   accum[0] = 1;

   secure_vector<word> t(2 * k_words);
   secure_vector<word> ws(2 * k_words);

   for(size_t i = 0; i != e_bits; ++i) {
      bigint_mul(t.data(), t.size(), g.data(), k_words, k_words, accum.data(), k_words, k_words, ws.data(), ws.size());
      t[k_words - 1] &= top_mask;
      CT::conditional_copy_mem(static_cast<word>(e.get_bit(i)), accum.data(), t.data(), accum.data(), k_words);

      bigint_sqr(t.data(), t.size(), g.data(), k_words, k_words, ws.data(), ws.size());
      t[k_words - 1] &= top_mask;
      copy_mem(g.data(), t.data(), k_words);
   }

   return BigInt::_from_words(accum);
}

}  // namespace

/*
* Modular Exponentiation
*/
BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod) {
   if(mod.signum() < 0 || mod == 1) {
      return BigInt::zero();
   }

   if(base.is_zero() || mod.is_zero()) {
      if(exp.is_zero()) {
         return BigInt::one();
      }
      return BigInt::zero();
   }

   const size_t exp_bits = exp.bits();

   if(mod.is_odd()) {
      const Montgomery_Params monty_params(mod);
      return monty_exp(monty_params, ct_modulo(base, mod), exp, exp_bits).value();
   }

   /*
   * Support for even modulus is just a convenience and not considered
   * cryptographically important.
   *
   * Write mod = 2^k * m with m odd, exponentiate modulo m and modulo 2^k
   * separately, then combine the results using CRT.
   */
   const BigInt g = ct_modulo(base, mod);
   const size_t k = low_zero_bits(mod);
   const BigInt m = mod >> k;

   BigInt r_2k = power_mod_pow2(g, exp, exp_bits, k);

   if(m == 1) {
      return r_2k;
   }

   const Montgomery_Params monty_m(m);
   const BigInt r_m = monty_exp(monty_m, ct_modulo(g, m), exp, exp_bits).value();

   // m is odd so it is always invertible modulo 2^k
   BigInt m_low = m;
   m_low.mask_bits(k);
   const BigInt m_inv = inverse_mod_general(m_low, BigInt::power_of_2(k)).value();

   // Compute h = (r_2k - r_m) * m^-1 mod 2^k, adding 2^k to keep the difference positive
   BigInt r_m_low = r_m;
   r_m_low.mask_bits(k);
   BigInt h = (r_2k + BigInt::power_of_2(k) - r_m_low) * m_inv;
   h.mask_bits(k);

   // Then r_m + h*m is congruent to r_m mod m and to r_2k mod 2^k
   return r_m + h * m;
}

/*
* Bitwise integer square root, which brings down two bits of C per iteration.
* The iteration count depends only on the size of C, so this is constant time
* with respect to its value.
*/
BigInt is_perfect_square(const BigInt& C) {
   if(C < 1) {
      throw Invalid_Argument("is_perfect_square requires C >= 1");
   }

   constexpr size_t WB = WordInfo<word>::bits;

   // The root r is less than 2^(bits(C)/2), and the remainder at most 8*r + 3
   const size_t n = C.sig_words() / 2 + 2;

   secure_vector<word> c(C._data(), C._data() + C.sig_words());
   secure_vector<word> r(n);
   secure_vector<word> rem(n);
   secure_vector<word> t(n);
   secure_vector<word> u(n);

   CT::poison(c);

   for(size_t i = (C.bits() + 1) / 2; i > 0; --i) {
      // Bring down the next two bits of C
      bigint_shl1(rem.data(), n, n, 2);
      rem[0] |= (c[(2 * i - 2) / WB] >> ((2 * i - 2) % WB)) & 3;

      // If rem >= 4*r + 1 then the next bit of the root is set
      copy_mem(t.data(), r.data(), n);
      bigint_shl1(t.data(), n, n, 2);
      t[0] |= 1;

      const word next_bit = bigint_sub3(u.data(), rem.data(), n, t.data(), n) ^ 1;
      CT::conditional_assign_mem(next_bit, rem.data(), u.data(), n);

      bigint_shl1(r.data(), n, n, 1);
      r[0] |= next_bit;
   }

   // C is a perfect square iff the remainder is zero
   (~CT::all_zeros(rem.data(), n)).if_set_zero_out(r.data(), n);
   CT::unpoison(r);

   return BigInt::_from_words(r);
}

namespace {

bool is_prime_impl(const BigInt& n, RandomNumberGenerator& rng, size_t prob, bool is_random, bool vartime) {
   if(n == 2) {
      return true;
   }
   if(n <= 1 || CT::driveby_unpoison(n.is_even())) {
      return false;
   }

   const size_t n_bits = n.bits();

   // Fast path testing for small numbers (<= 65521)
   if(n_bits <= 16) {
      const uint16_t num = static_cast<uint16_t>(n.word_at(0));

      return std::binary_search(PRIMES, PRIMES + PRIME_TABLE_SIZE, num);
   }

   // Trial division, which is much cheaper than the Miller-Rabin setup below
   const auto residues = mod_small_primes(n, std::min(n_bits, PRIME_TABLE_SIZE));

   auto no_small_factor = CT::Mask<word>::set();
   for(const word r : residues) {
      // We've already checked above that n is not itself in the primes table, so any
      // remainder of zero implies a factor rather than equality
      no_small_factor &= CT::Mask<word>::expand(r);
   }

   if(!no_small_factor.as_bool()) {
      return false;
   }

   const Montgomery_Params monty_n(n);

   if(rng.is_seeded()) {
      const size_t t = miller_rabin_test_iterations(n_bits, prob, is_random);

      if(is_random) {
         return vartime ? is_miller_rabin_probable_prime_vartime(n, monty_n, rng, t)
                        : is_miller_rabin_probable_prime(n, monty_n, rng, t);
      } else {
         return vartime ? is_miller_rabin_lucas_probable_prime_vartime(n, monty_n, rng, t)
                        : is_miller_rabin_lucas_probable_prime(n, monty_n, rng, t);
      }
   } else {
      return vartime ? is_bailie_psw_probable_prime_vartime(n, monty_n) : is_bailie_psw_probable_prime(n, monty_n);
   }
}

}  // namespace

/*
* Test for primality using Miller-Rabin
*/
bool is_prime(const BigInt& n, RandomNumberGenerator& rng, size_t prob, bool is_random) {
   return is_prime_impl(n, rng, prob, is_random, false);
}

bool is_prime_vartime(const BigInt& n, RandomNumberGenerator& rng, size_t prob, bool is_random) {
   return is_prime_impl(n, rng, prob, is_random, true);
}

}  // namespace Botan
