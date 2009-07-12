/*
* Number Theory Functions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/numthry.h>
#include <botan/bit_ops.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* Miller-Rabin Iterations
*/
u32bit miller_rabin_test_iterations(u32bit bits, bool verify)
   {
   struct mapping { u32bit bits; u32bit verify_iter; u32bit check_iter; };

   static const mapping tests[] = {
      {   50, 55, 25 },
      {  100, 38, 22 },
      {  160, 32, 18 },
      {  163, 31, 17 },
      {  168, 30, 16 },
      {  177, 29, 16 },
      {  181, 28, 15 },
      {  185, 27, 15 },
      {  190, 26, 15 },
      {  195, 25, 14 },
      {  201, 24, 14 },
      {  208, 23, 14 },
      {  215, 22, 13 },
      {  222, 21, 13 },
      {  231, 20, 13 },
      {  241, 19, 12 },
      {  252, 18, 12 },
      {  264, 17, 12 },
      {  278, 16, 11 },
      {  294, 15, 10 },
      {  313, 14,  9 },
      {  334, 13,  8 },
      {  360, 12,  8 },
      {  392, 11,  7 },
      {  430, 10,  7 },
      {  479,  9,  6 },
      {  542,  8,  6 },
      {  626,  7,  5 },
      {  746,  6,  4 },
      {  926,  5,  3 },
      { 1232,  4,  2 },
      { 1853,  3,  2 },
      {    0,  0,  0 }
   };

   for(u32bit i = 0; tests[i].bits; ++i)
      {
      if(bits <= tests[i].bits)
         {
         if(verify)
            return tests[i].verify_iter;
         else
            return tests[i].check_iter;
         }
      }
   return 2;
   }

}

/*
* Return the number of 0 bits at the end of n
*/
u32bit low_zero_bits(const BigInt& n)
   {
   if(n.is_negative() || n.is_zero()) return 0;

   u32bit low_zero = 0;

   if(n.is_positive() && n.is_nonzero())
      {
      for(u32bit i = 0; i != n.size(); ++i)
         {
         word x = n[i];

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
   if(a.is_zero() || b.is_zero()) return 0;
   if(a == 1 || b == 1)           return 1;

   BigInt x = a, y = b;
   x.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);
   u32bit shift = std::min(low_zero_bits(x), low_zero_bits(y));

   x >>= shift;
   y >>= shift;

   while(x.is_nonzero())
      {
      x >>= low_zero_bits(x);
      y >>= low_zero_bits(y);
      if(x >= y) { x -= y; x >>= 1; }
      else       { y -= x; y >>= 1; }
      }

   return (y << shift);
   }

/*
* Calculate the LCM
*/
BigInt lcm(const BigInt& a, const BigInt& b)
   {
   return ((a * b) / gcd(a, b));
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

   if(n.is_zero() || (n.is_even() && mod.is_even()))
      return 0;

   BigInt x = mod, y = n, u = mod, v = n;
   BigInt A = 1, B = 0, C = 0, D = 1;

   while(u.is_nonzero())
      {
      u32bit zero_bits = low_zero_bits(u);
      u >>= zero_bits;
      for(u32bit i = 0; i != zero_bits; ++i)
         {
         if(A.is_odd() || B.is_odd())
            { A += y; B -= x; }
         A >>= 1; B >>= 1;
         }

      zero_bits = low_zero_bits(v);
      v >>= zero_bits;
      for(u32bit i = 0; i != zero_bits; ++i)
         {
         if(C.is_odd() || D.is_odd())
            { C += y; D -= x; }
         C >>= 1; D >>= 1;
         }

      if(u >= v) { u -= v; A -= C; B -= D; }
      else       { v -= u; C -= A; D -= B; }
      }

   if(v != 1)
      return 0;

   while(D.is_negative()) D += mod;
   while(D >= mod) D -= mod;

   return D;
   }

/*
* Modular Exponentiation
*/
BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod)
   {
   Power_Mod pow_mod(mod);
   pow_mod.set_base(base);
   pow_mod.set_exponent(exp);
   return pow_mod.execute();
   }

/*
* Do simple tests of primality
*/
s32bit simple_primality_tests(const BigInt& n)
   {
   const s32bit NOT_PRIME = -1, UNKNOWN = 0, PRIME = 1;

   if(n == 2)
      return PRIME;
   if(n <= 1 || n.is_even())
      return NOT_PRIME;

   if(n <= PRIMES[PRIME_TABLE_SIZE-1])
      {
      const word num = n.word_at(0);
      for(u32bit i = 0; PRIMES[i]; ++i)
         {
         if(num == PRIMES[i]) return PRIME;
         if(num <  PRIMES[i]) return NOT_PRIME;
         }
      return NOT_PRIME;
      }

   u32bit check_first = std::min(n.bits() / 32, PRIME_PRODUCTS_TABLE_SIZE);
   for(u32bit i = 0; i != check_first; ++i)
      if(gcd(n, PRIME_PRODUCTS[i]) != 1)
         return NOT_PRIME;

   return UNKNOWN;
   }

/*
* Fast check of primality
*/
bool check_prime(const BigInt& n, RandomNumberGenerator& rng)
   {
   return run_primality_tests(rng, n, 0);
   }

/*
* Test for primality
*/
bool is_prime(const BigInt& n, RandomNumberGenerator& rng)
   {
   return run_primality_tests(rng, n, 1);
   }

/*
* Verify primality
*/
bool verify_prime(const BigInt& n, RandomNumberGenerator& rng)
   {
   return run_primality_tests(rng, n, 2);
   }

/*
* Verify primality
*/
bool run_primality_tests(RandomNumberGenerator& rng,
                         const BigInt& n, u32bit level)
   {
   s32bit simple_tests = simple_primality_tests(n);
   if(simple_tests) return (simple_tests == 1) ? true : false;
   return passes_mr_tests(rng, n, level);
   }

/*
* Test for primaility using Miller-Rabin
*/
bool passes_mr_tests(RandomNumberGenerator& rng,
                     const BigInt& n, u32bit level)
   {
   const u32bit PREF_NONCE_BITS = 40;

   if(level > 2)
      level = 2;

   MillerRabin_Test mr(n);

   if(!mr.passes_test(2))
      return false;

   if(level == 0)
      return true;

   const u32bit NONCE_BITS = std::min(n.bits() - 1, PREF_NONCE_BITS);

   const bool verify = (level == 2);

   u32bit tests = miller_rabin_test_iterations(n.bits(), verify);

   BigInt nonce;
   for(u32bit i = 0; i != tests; ++i)
      {
      if(!verify && PRIMES[i] < (n-1))
         nonce = PRIMES[i];
      else
         {
         while(nonce < 2 || nonce >= (n-1))
            nonce.randomize(rng, NONCE_BITS);
         }

      if(!mr.passes_test(nonce))
         return false;
      }
   return true;
   }

/*
* Miller-Rabin Test
*/
bool MillerRabin_Test::passes_test(const BigInt& a)
   {
   if(a < 2 || a >= n_minus_1)
      throw Invalid_Argument("Bad size for nonce in Miller-Rabin test");

   BigInt y = pow_mod(a);
   if(y == 1 || y == n_minus_1)
      return true;

   for(u32bit i = 1; i != s; ++i)
      {
      y = reducer.square(y);

      if(y == 1)
         return false;
      if(y == n_minus_1)
         return true;
      }
   return false;
   }

/*
* Miller-Rabin Constructor
*/
MillerRabin_Test::MillerRabin_Test(const BigInt& num)
   {
   if(num.is_even() || num < 3)
      throw Invalid_Argument("MillerRabin_Test: Invalid number for testing");

   n = num;
   n_minus_1 = n - 1;
   s = low_zero_bits(n_minus_1);
   r = n_minus_1 >> s;

   pow_mod = Fixed_Exponent_Power_Mod(r, n);
   reducer = Modular_Reducer(n);
   }

}
