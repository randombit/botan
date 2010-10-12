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
* Fused multiply-add
* @param a an integer
* @param b an integer
* @param c an integer
* @return (a*b)+c
*/
BigInt BOTAN_DLL mul_add(const BigInt& a,
                         const BigInt& b,
                         const BigInt& c);

/**
* Fused subtract-multiply
* @param a an integer
* @param b an integer
* @param c an integer
* @return (a-b)*c
*/
BigInt BOTAN_DLL sub_mul(const BigInt& a,
                         const BigInt& b,
                         const BigInt& c);

/**
* Return the absolute value
* @param n an integer
* @return absolute value of n
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
* @param b an integer base
* @param x a positive exponent
* @param m a positive modulus
* @return (b^x) % m
*/
BigInt BOTAN_DLL power_mod(const BigInt& b,
                           const BigInt& x,
                           const BigInt& m);

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
size_t BOTAN_DLL low_zero_bits(const BigInt& x);

/**
* Primality Testing
* @param n a positive integer to test for primality
* @param rng a random number generator
* @param level how hard to test
* @return true if all primality tests passed, otherwise false
*/
bool BOTAN_DLL primality_test(const BigInt& n,
                              RandomNumberGenerator& rng,
                              size_t level = 1);

/**
* Quickly check for primality
* @param n a positive integer to test for primality
* @param rng a random number generator
* @return true if all primality tests passed, otherwise false
*/
inline bool quick_check_prime(const BigInt& n, RandomNumberGenerator& rng)
   { return primality_test(n, rng, 0); }

/**
* Check for primality
* @param n a positive integer to test for primality
* @param rng a random number generator
* @return true if all primality tests passed, otherwise false
*/
inline bool check_prime(const BigInt& n, RandomNumberGenerator& rng)
   { return primality_test(n, rng, 1); }

/**
* Verify primality - this function is slow but useful if you want to
* ensure that a possibly malicious entity did not provide you with
* something that 'looks like' a prime
* @param n a positive integer to test for primality
* @param rng a random number generator
* @return true if all primality tests passed, otherwise false
*/
inline bool verify_prime(const BigInt& n, RandomNumberGenerator& rng)
   { return primality_test(n, rng, 2); }

/**
* Randomly generate a prime
* @param rng a random number generator
* @param bits how large the resulting prime should be in bits
* @param coprime a positive integer the result should be coprime to
* @param equiv a non-negative number that the result should be
               equivalent to modulo equiv_mod
* @param equiv_mod the modulus equiv should be checked against
* @return random prime with the specified criteria
*/
BigInt BOTAN_DLL random_prime(RandomNumberGenerator& rng,
                              size_t bits, const BigInt& coprime = 1,
                              size_t equiv = 1, size_t equiv_mod = 2);

/**
* Return a 'safe' prime, of the form p=2*q+1 with q prime
* @param rng a random number generator
* @param bits is how long the resulting prime should be
* @return prime randomly chosen from safe primes of length bits
*/
BigInt BOTAN_DLL random_safe_prime(RandomNumberGenerator& rng,
                                   size_t bits);

class Algorithm_Factory;

/**
* Generate DSA parameters using the FIPS 186 kosherizer
* @param rng a random number generator
* @param af an algorithm factory
* @param p_out where the prime p will be stored
* @param q_out where the prime q will be stored
* @param pbits how long p will be in bits
* @param qbits how long q will be in bits
* @return random seed used to generate this parameter set
*/
SecureVector<byte> BOTAN_DLL
generate_dsa_primes(RandomNumberGenerator& rng,
                    Algorithm_Factory& af,
                    BigInt& p_out, BigInt& q_out,
                    size_t pbits, size_t qbits);

/**
* Generate DSA parameters using the FIPS 186 kosherizer
* @param rng a random number generator
* @param af an algorithm factory
* @param p_out where the prime p will be stored
* @param q_out where the prime q will be stored
* @param pbits how long p will be in bits
* @param qbits how long q will be in bits
* @param seed the seed used to generate the parameters
* @return true if seed generated a valid DSA parameter set, otherwise
          false. p_out and q_out are only valid if true was returned.
*/
bool BOTAN_DLL
generate_dsa_primes(RandomNumberGenerator& rng,
                    Algorithm_Factory& af,
                    BigInt& p_out, BigInt& q_out,
                    size_t pbits, size_t qbits,
                    const MemoryRegion<byte>& seed);

/**
* The size of the PRIMES[] array
*/
const size_t PRIME_TABLE_SIZE = 6541;

/**
* A const array of all primes less than 65535
*/
extern const u16bit BOTAN_DLL PRIMES[];

}

#endif
