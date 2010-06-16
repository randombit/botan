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

/**
* Fused Arithmetic Operation
*/
BigInt BOTAN_DLL mul_add(const BigInt&, const BigInt&, const BigInt&);
BigInt BOTAN_DLL sub_mul(const BigInt&, const BigInt&, const BigInt&);

/*
* Number Theory Functions
*/
inline BigInt abs(const BigInt& n) { return n.abs(); }

/**
* Compute the greatest common divisor
* @param x a positive integer
* @param y a positive integer
* @return gcd(x,y)
*/
BigInt BOTAN_DLL gcd(const BigInt& x, const BigInt& y);

/**
* Least common multiple
* @param x a positive integer
* @param y a positive integer
* @return z, smallest integer such that z % x == 0 and z % y == 0
*/
BigInt BOTAN_DLL lcm(const BigInt& x, const BigInt& y);

/**
* @param x an integer
* @return (x*x)
*/
BigInt BOTAN_DLL square(const BigInt& x);

/**
* Modular inversion
* @param x a positive integer
* @param modulus a positive integer
* @return y st (x*y) % modulus == 1
*/
BigInt BOTAN_DLL inverse_mod(const BigInt& x,
                             const BigInt& modulus);

/**
* Compute the Jacobi symbol. If n is prime, this is equivalent
* to the Legendre symbol.
* @see http://mathworld.wolfram.com/JacobiSymbol.html
*
* @param a is a non-negative integer
* @param n is an odd integer > 1
* @return (n / m)
*/
s32bit BOTAN_DLL jacobi(const BigInt& a,
                        const BigInt& n);

/**
* Modular exponentation
*/
BigInt BOTAN_DLL power_mod(const BigInt&, const BigInt&, const BigInt&);

/**
* Compute the square root of x modulo a prime using the
* Shanks-Tonnelli algorithm
*
* @param x the input
* @param p the prime
* @return y such that (y*y)%p == x, or -1 if no such integer
*/
BigInt BOTAN_DLL ressol(const BigInt& x, const BigInt& p);

/**
* @param x an integer
* @return count of the zero bits in x, or, equivalently, the largest
* value of n such that 2^n divides x evently
*/
u32bit BOTAN_DLL low_zero_bits(const BigInt& x);

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
