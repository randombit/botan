/*
* Number Theory Functions
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/mp_core.h>
#include <algorithm>

namespace Botan {

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
   if(a.is_zero() || b.is_zero()) return 0;
   if(a == 1 || b == 1)           return 1;

   BigInt x = a, y = b;
   x.set_sign(BigInt::Positive);
   y.set_sign(BigInt::Positive);
   size_t shift = std::min(low_zero_bits(x), low_zero_bits(y));

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

namespace {

/*
* If the modulus is odd, then we can avoid computing A and C. This is
* a critical path algorithm in some instances and an odd modulus is
* the common case for crypto, so worth special casing. See note 14.64
* in Handbook of Applied Cryptography for more details.
*/
BigInt inverse_mod_odd_modulus(const BigInt& n, const BigInt& mod)
   {
   BigInt u = mod, v = n;
   BigInt B = 0, D = 1;

   while(u.is_nonzero())
      {
      const size_t u_zero_bits = low_zero_bits(u);
      u >>= u_zero_bits;
      for(size_t i = 0; i != u_zero_bits; ++i)
         {
         if(B.is_odd())
            { B -= mod; }
         B >>= 1;
         }

      const size_t v_zero_bits = low_zero_bits(v);
      v >>= v_zero_bits;
      for(size_t i = 0; i != v_zero_bits; ++i)
         {
         if(D.is_odd())
            { D -= mod; }
         D >>= 1;
         }

      if(u >= v) { u -= v; B -= D; }
      else       { v -= u; D -= B; }
      }

   if(v != 1)
      return 0; // no modular inverse

   while(D.is_negative()) D += mod;
   while(D >= mod) D -= mod;

   return D;
   }

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
      return 0; // fast fail checks

   if(mod.is_odd())
      return inverse_mod_odd_modulus(n, mod);

   BigInt u = mod, v = n;
   BigInt A = 1, B = 0, C = 0, D = 1;

   while(u.is_nonzero())
      {
      const size_t u_zero_bits = low_zero_bits(u);
      u >>= u_zero_bits;
      for(size_t i = 0; i != u_zero_bits; ++i)
         {
         if(A.is_odd() || B.is_odd())
            { A += n; B -= mod; }
         A >>= 1; B >>= 1;
         }

      const size_t v_zero_bits = low_zero_bits(v);
      v >>= v_zero_bits;
      for(size_t i = 0; i != v_zero_bits; ++i)
         {
         if(C.is_odd() || D.is_odd())
            { C += n; D -= mod; }
         C >>= 1; D >>= 1;
         }

      if(u >= v) { u -= v; A -= C; B -= D; }
      else       { v -= u; C -= A; D -= B; }
      }

   if(v != 1)
      return 0; // no modular inverse

   while(D.is_negative()) D += mod;
   while(D >= mod) D -= mod;

   return D;
   }

word monty_inverse(word input)
   {
   word b = input;
   word x2 = 1, x1 = 0, y2 = 0, y1 = 1;

   // First iteration, a = n+1
   word q = bigint_divop(1, 0, b);
   word r = (MP_WORD_MAX - q*b) + 1;
   word x = x2 - q*x1;
   word y = y2 - q*y1;

   word a = b;
   b = r;
   x2 = x1;
   x1 = x;
   y2 = y1;
   y1 = y;

   while(b > 0)
      {
      q = a / b;
      r = a - q*b;
      x = x2 - q*x1;
      y = y2 - q*y1;

      a = b;
      b = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
      }

   // Now invert in addition space
   y2 = (MP_WORD_MAX - y2) + 1;

   return y2;
   }

/*
* Modular Exponentiation
*/
BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod)
   {
   Power_Mod pow_mod(mod);

   /*
   * Calling set_base before set_exponent means we end up using a
   * minimal window. This makes sense given that here we know that any
   * precomputation is wasted.
   */
   pow_mod.set_base(base);
   pow_mod.set_exponent(exp);
   return pow_mod.execute();
   }

namespace {

bool mr_witness(BigInt&& y,
                const Modular_Reducer& reducer_n,
                const BigInt& n_minus_1, size_t s)
   {
   if(y == 1 || y == n_minus_1)
      return false;

   for(size_t i = 1; i != s; ++i)
      {
      y = reducer_n.square(y);

      if(y == 1) // found a non-trivial square root
         return true;

      if(y == n_minus_1) // -1, trivial square root, so give up
         return false;
      }

   return true; // fails Fermat test
   }

size_t mr_test_iterations(size_t n_bits, size_t prob, bool random)
   {
   const size_t base = (prob + 2) / 2; // worst case 4^-t error rate

   /*
   * For randomly chosen numbers we can use the estimates from
   * http://www.math.dartmouth.edu/~carlp/PDF/paper88.pdf‎
   *
   * These values are derived from the inequality for p(k,t) given on
   * the second page.
   */
   if(random && prob <= 80)
      {
      if(n_bits >= 1536)
         return 2; // < 2^-89
      if(n_bits >= 1024)
         return 4; // < 2^-89
      if(n_bits >= 512)
         return 5; // < 2^-80
      if(n_bits >= 256)
         return 11; // < 2^-80
      }

   return base;
   }

}

/*
* Test for primaility using Miller-Rabin
*/
bool is_prime(const BigInt& n, RandomNumberGenerator& rng,
              size_t prob, bool is_random)
   {
   if(n == 2)
      return true;
   if(n <= 1 || n.is_even())
      return false;

   // Fast path testing for small numbers (<= 65521)
   if(n <= PRIMES[PRIME_TABLE_SIZE-1])
      {
      const u16bit num = n.word_at(0);

      return std::binary_search(PRIMES, PRIMES + PRIME_TABLE_SIZE, num);
      }

   const size_t test_iterations = mr_test_iterations(n.bits(), prob, is_random);

   const BigInt n_minus_1 = n - 1;
   const size_t s = low_zero_bits(n_minus_1);

   Fixed_Exponent_Power_Mod pow_mod(n_minus_1 >> s, n);
   Modular_Reducer reducer(n);

   for(size_t i = 0; i != test_iterations; ++i)
      {
      const BigInt a = BigInt::random_integer(rng, 2, n_minus_1);

      BigInt y = pow_mod(a);

      if(mr_witness(std::move(y), reducer, n_minus_1, s))
         return false;
      }

   return true;
   }

}
