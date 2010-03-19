/*
* Number Theory Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NUMBER_THEORY_H__
#define BOTAN_NUMBER_THEORY_H__

#include <botan/bigint.h>
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

BigInt BOTAN_DLL gcd(const BigInt& x, const BigInt& y);
BigInt BOTAN_DLL lcm(const BigInt& x, const BigInt& y);

BigInt BOTAN_DLL square(const BigInt&);
BigInt BOTAN_DLL inverse_mod(const BigInt&, const BigInt&);
s32bit BOTAN_DLL jacobi(const BigInt&, const BigInt&);

BigInt BOTAN_DLL power_mod(const BigInt&, const BigInt&, const BigInt&);

/*
* Compute the square root of x modulo a prime
* using the Shanks-Tonnelli algorithm
*/
BigInt BOTAN_DLL ressol(const BigInt& x, const BigInt& p);

/*
* Utility Functions
*/
u32bit BOTAN_DLL low_zero_bits(const BigInt&);

/*
* Primality Testing
*/
bool BOTAN_DLL primality_test(const BigInt& n,
                              RandomNumberGenerator& rng,
                              u32bit level = 1);

inline bool quick_check_prime(const BigInt& n, RandomNumberGenerator& rng)
   { return primality_test(n, rng, 0); }

inline bool check_prime(const BigInt& n, RandomNumberGenerator& rng)
   { return primality_test(n, rng, 1); }

inline bool verify_prime(const BigInt& n, RandomNumberGenerator& rng)
   { return primality_test(n, rng, 2); }

/*
* Random Number Generation
*/
BigInt BOTAN_DLL random_prime(RandomNumberGenerator& rng,
                              u32bit bits, const BigInt& coprime = 1,
                              u32bit equiv = 1, u32bit equiv_mod = 2);

BigInt BOTAN_DLL random_safe_prime(RandomNumberGenerator& rng,
                                   u32bit bits);

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

extern const u16bit BOTAN_DLL PRIMES[];

}

#endif
