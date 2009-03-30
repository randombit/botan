/*
* Number Theory Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NUMBER_THEORY_H__
#define BOTAN_NUMBER_THEORY_H__

#include <botan/bigint.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>
#include <botan/rng.h>

namespace Botan {

/*
* Fused Arithmetic Operations
*/
BigInt BOTAN_DLL mul_add(const BigInt&, const BigInt&, const BigInt&);
BigInt BOTAN_DLL sub_mul(const BigInt&, const BigInt&, const BigInt&);

/*
* Number Theory Functions
*/
inline BigInt abs(const BigInt& n) { return n.abs(); }

void BOTAN_DLL divide(const BigInt&, const BigInt&, BigInt&, BigInt&);

BigInt BOTAN_DLL gcd(const BigInt&, const BigInt&);
BigInt BOTAN_DLL lcm(const BigInt&, const BigInt&);

BigInt BOTAN_DLL square(const BigInt&);
BigInt BOTAN_DLL inverse_mod(const BigInt&, const BigInt&);
s32bit BOTAN_DLL jacobi(const BigInt&, const BigInt&);

BigInt BOTAN_DLL power_mod(const BigInt&, const BigInt&, const BigInt&);

/*
* Compute the square root of x modulo a prime
* using the Shanks-Tonnelli algorithm
*/
BigInt ressol(const BigInt& x, const BigInt& p);

/*
* Utility Functions
*/
u32bit BOTAN_DLL low_zero_bits(const BigInt&);

/*
* Primality Testing
*/
bool BOTAN_DLL check_prime(const BigInt&, RandomNumberGenerator&);
bool BOTAN_DLL is_prime(const BigInt&, RandomNumberGenerator&);
bool BOTAN_DLL verify_prime(const BigInt&, RandomNumberGenerator&);

s32bit BOTAN_DLL simple_primality_tests(const BigInt&);

bool BOTAN_DLL passes_mr_tests(RandomNumberGenerator&,
                               const BigInt&, u32bit = 1);

bool BOTAN_DLL run_primality_tests(RandomNumberGenerator&,
                                   const BigInt&, u32bit = 1);

/*
* Random Number Generation
*/
BigInt BOTAN_DLL random_prime(RandomNumberGenerator&,
                              u32bit bits, const BigInt& coprime = 1,
                              u32bit equiv = 1, u32bit equiv_mod = 2);

BigInt BOTAN_DLL random_safe_prime(RandomNumberGenerator&,
                                   u32bit);

/*
* DSA Parameter Generation
*/
class Algorithm_Factory;

SecureVector<byte> BOTAN_DLL
generate_dsa_primes(RandomNumberGenerator& rng,
                    Algorithm_Factory& af,
                    BigInt& p, BigInt& q,
                    u32bit pbits, u32bit qbits);

bool BOTAN_DLL
generate_dsa_primes(RandomNumberGenerator& rng,
                    Algorithm_Factory& af,
                    BigInt& p_out, BigInt& q_out,
                    u32bit p_bits, u32bit q_bits,
                    const MemoryRegion<byte>& seed);

/*
* Prime Numbers
*/
const u32bit PRIME_TABLE_SIZE = 6541;
const u32bit PRIME_PRODUCTS_TABLE_SIZE = 256;

extern const u16bit BOTAN_DLL PRIMES[];
extern const u64bit PRIME_PRODUCTS[];

/*
* Miller-Rabin Primality Tester
*/
class BOTAN_DLL MillerRabin_Test
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
