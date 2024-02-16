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
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/primality.h>
#include <algorithm>

namespace Botan {

/*
* Return the number of 0 bits at the end of n
*/
size_t low_zero_bits(const BigInt& n)
   {
   size_t low_zero = 0;

   auto seen_nonempty_word = CT::Mask<word>::cleared();

   for(size_t i = 0; i != n.size(); ++i)
      {
      const word x = n.word_at(i);

      // ctz(0) will return sizeof(word)
      const size_t tz_x = ctz(x);

      // if x > 0 we want to count tz_x in total but not any
      // further words, so set the mask after the addition
      low_zero += seen_nonempty_word.if_not_set_return(tz_x);

      seen_nonempty_word |= CT::Mask<word>::expand(x);
      }

   // if we saw no words with x > 0 then n == 0 and the value we have
   // computed is meaningless. Instead return 0 in that case.
   return seen_nonempty_word.if_set_return(low_zero);
   }

/*
* Calculate the GCD in constant time
*/
BigInt gcd(const BigInt& a, const BigInt& b)
   {
   if(a.is_zero())
      return abs(b);
   if(b.is_zero())
      return abs(a);

   if(a == 1 || b == 1)
      return 1;

   const size_t sz = std::max(a.sig_words(), b.sig_words());
   auto u = BigInt::with_capacity(sz);
   auto v = BigInt::with_capacity(sz);
   u += a;
   v += b;

   u.const_time_poison();
   v.const_time_poison();

   u.set_sign(BigInt::Positive);
   v.set_sign(BigInt::Positive);

   // In the worst case we have two fully populated big ints. After right
   // shifting so many times, we'll have reached the result for sure.
   const size_t loop_cnt = u.bits() + v.bits();

   using WordMask = CT::Mask<word>;

   // This temporary is big enough to hold all intermediate results of the
   // algorithm. No reallocation will happen during the loop.
   // Note however, that `ct_cond_assign()` will invalidate the 'sig_words'
   // cache, which _does not_ shrink the capacity of the underlying buffer.
   auto tmp = BigInt::with_capacity(sz);
   size_t factors_of_two = 0;
   for(size_t i = 0; i != loop_cnt; ++i) {
      auto both_odd = WordMask::expand(u.is_odd()) & WordMask::expand(v.is_odd());

      // Subtract the smaller from the larger if both are odd
      auto u_gt_v = WordMask::expand(bigint_cmp(u.data(), u.size(), v.data(), v.size()) > 0);
      bigint_sub_abs(tmp.mutable_data(), u.data(), sz, v.data(), sz);
      u.ct_cond_assign((u_gt_v & both_odd).is_set(), tmp);
      v.ct_cond_assign((~u_gt_v & both_odd).is_set(), tmp);

      const auto u_is_even = WordMask::expand(u.is_even());
      const auto v_is_even = WordMask::expand(v.is_even());
      BOTAN_DEBUG_ASSERT((u_is_even | v_is_even).is_set());

      // When both are even, we're going to eliminate a factor of 2.
      // We have to reapply this factor to the final result.
      factors_of_two += (u_is_even & v_is_even).if_set_return(1);

      // remove one factor of 2, if u is even
      bigint_shr2(tmp.mutable_data(), u.data(), sz, 0, 1);
      u.ct_cond_assign(u_is_even.is_set(), tmp);

      // remove one factor of 2, if v is even
      bigint_shr2(tmp.mutable_data(), v.data(), sz, 0, 1);
      v.ct_cond_assign(v_is_even.is_set(), tmp);
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

   u.const_time_unpoison();
   v.const_time_unpoison();

   return u;
}

/*
* Calculate the LCM
*/
BigInt lcm(const BigInt& a, const BigInt& b)
   {
   return ct_divide(a * b, gcd(a, b));
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

      if(is_random)
         return true;
      else
         return is_lucas_probable_prime(n, mod_n);
      }
   else
      {
      return is_bailie_psw_probable_prime(n, mod_n);
      }
   }

}
