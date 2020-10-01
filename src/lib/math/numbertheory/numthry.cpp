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
* Calculate the GCD
*/
BigInt gcd(const BigInt& a, const BigInt& b)
   {
   if(a.is_zero() || b.is_zero())
      return 0;
   if(a == 1 || b == 1)
      return 1;

   // See https://gcd.cr.yp.to/safegcd-20190413.pdf fig 1.2

   BigInt f = a;
   BigInt g = b;
   f.const_time_poison();
   g.const_time_poison();

   f.set_sign(BigInt::Positive);
   g.set_sign(BigInt::Positive);

   const size_t common2s = std::min(low_zero_bits(f), low_zero_bits(g));
   CT::unpoison(common2s);

   f >>= common2s;
   g >>= common2s;

   f.ct_cond_swap(f.is_even(), g);

   int32_t delta = 1;

   const size_t loop_cnt = 4 + 3*std::max(f.bits(), g.bits());

   BigInt newg, t;
   for(size_t i = 0; i != loop_cnt; ++i)
      {
      sub_abs(newg, f, g);

      const bool need_swap = (g.is_odd() && delta > 0);

      // if(need_swap) delta *= -1
      delta *= CT::Mask<uint8_t>::expand(need_swap).select(0, 2) - 1;
      f.ct_cond_swap(need_swap, g);
      g.ct_cond_swap(need_swap, newg);

      delta += 1;

      g.ct_cond_add(g.is_odd(), f);
      g >>= 1;
      }

   f <<= common2s;

   f.const_time_unpoison();
   g.const_time_unpoison();

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
