/*************************************************
* Number Theory Header File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_NUMBTHRY_H__
#define BOTAN_NUMBTHRY_H__

#include <botan/bigint.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>

namespace Botan {

/*************************************************
* Fused Arithmetic Operations                    *
*************************************************/
BigInt mul_add(const BigInt&, const BigInt&, const BigInt&);
BigInt sub_mul(const BigInt&, const BigInt&, const BigInt&);

/*************************************************
* Number Theory Functions                        *
*************************************************/
inline BigInt abs(const BigInt& n) { return n.abs(); }

void divide(const BigInt&, const BigInt&, BigInt&, BigInt&);

BigInt gcd(const BigInt&, const BigInt&);
BigInt lcm(const BigInt&, const BigInt&);

BigInt square(const BigInt&);
BigInt inverse_mod(const BigInt&, const BigInt&);
s32bit jacobi(const BigInt&, const BigInt&);

BigInt power_mod(const BigInt&, const BigInt&, const BigInt&);

/*************************************************
* Utility Functions                              *
*************************************************/
u32bit low_zero_bits(const BigInt&);

/*************************************************
* Primality Testing                              *
*************************************************/
bool check_prime(const BigInt&);
bool is_prime(const BigInt&);
bool verify_prime(const BigInt&);

s32bit simple_primality_tests(const BigInt&);
bool passes_mr_tests(const BigInt&, u32bit = 1);
bool run_primality_tests(const BigInt&, u32bit = 1);

/*************************************************
* Random Number Generation                       *
*************************************************/
BigInt random_integer(u32bit);
BigInt random_integer(const BigInt&, const BigInt&);
BigInt random_prime(u32bit, const BigInt& = 1, u32bit = 1, u32bit = 2);
BigInt random_safe_prime(u32bit);

/*************************************************
* Prime Numbers                                  *
*************************************************/
const u32bit PRIME_TABLE_SIZE = 6541;
const u32bit PRIME_PRODUCTS_TABLE_SIZE = 256;

extern const u16bit PRIMES[];
extern const u64bit PRIME_PRODUCTS[];

/*************************************************
* Miller-Rabin Primality Tester                  *
*************************************************/
class MillerRabin_Test
   {
   public:
      bool passes_test(const BigInt&);
      MillerRabin_Test(const BigInt&);
   private:
      BigInt n, r, n_minus_1;
      u32bit s;
      Fixed_Exponent_Power_Mod pow_mod;
      Modular_Reducer reducer;
   };

}

#endif
