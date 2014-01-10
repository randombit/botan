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

namespace {

/*
* Miller-Rabin Primality Tester
*/
class MillerRabin_Test
   {
   public:
      bool is_witness(const BigInt& nonce);
      MillerRabin_Test(const BigInt& num);
   private:
      BigInt n, r, n_minus_1;
      size_t s;
      Fixed_Exponent_Power_Mod pow_mod;
      Modular_Reducer reducer;
   };

/*
* Miller-Rabin Test, as described in Handbook of Applied Cryptography
* section 4.24
*/
bool MillerRabin_Test::is_witness(const BigInt& a)
   {
   if(a < 2 || a >= n_minus_1)
      throw Invalid_Argument("Bad size for nonce in Miller-Rabin test");

   BigInt y = pow_mod(a);
   if(y == 1 || y == n_minus_1)
      return false;

   for(size_t i = 1; i != s; ++i)
      {
      y = reducer.square(y);

      if(y == 1) // found a non-trivial square root
         return true;

      if(y == n_minus_1) // -1, trivial square root, so give up
         return false;
      }

   if(y != n_minus_1) // fails Fermat test
      return true;

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

/*
* Miller-Rabin Iterations
*/
size_t miller_rabin_test_iterations(size_t bits, size_t level)
   {
   struct mapping { size_t bits; size_t verify_iter; size_t check_iter; };

   const mapping tests[] = {
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

   for(size_t i = 0; tests[i].bits; ++i)
      {
      if(bits <= tests[i].bits)
         {
         if(level >= 2)
            return tests[i].verify_iter;
         else if(level == 1)
            return tests[i].check_iter;
         else if(level == 0)
            return std::max<size_t>(tests[i].check_iter / 4, 1);
         }
      }

   return level > 0 ? 2 : 1; // for large inputs
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

/*
* Test for primaility using Miller-Rabin
*/
bool primality_test(const BigInt& n,
                    RandomNumberGenerator& rng,
                    size_t level)
   {
   if(n == 2)
      return true;
   if(n <= 1 || n.is_even())
      return false;

   // Fast path testing for small numbers (<= 65521)
   if(n <= PRIMES[PRIME_TABLE_SIZE-1])
      {
      const word num = n.word_at(0);

      for(size_t i = 0; PRIMES[i]; ++i)
         {
         if(num == PRIMES[i])
            return true;
         if(num < PRIMES[i])
            return false;
         }

      return false;
      }

   if(level > 2)
      level = 2;

   const size_t PREF_NONCE_BITS = 192;

   const size_t NONCE_BITS = std::min(n.bits() - 2, PREF_NONCE_BITS);

   MillerRabin_Test mr(n);

   const size_t tests = miller_rabin_test_iterations(n.bits(), level);

   BigInt nonce;
   for(size_t i = 0; i != tests; ++i)
      {
      while(nonce < 2 || nonce >= (n-1))
         nonce.randomize(rng, NONCE_BITS);

      if(mr.is_witness(nonce))
         return false;
      }
   return true;
   }

}
