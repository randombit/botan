/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MOD_INV_H_
#define BOTAN_MOD_INV_H_

#include <botan/bigint.h>
#include <optional>

namespace Botan {

/**
* Compute the inverse of x modulo some integer m
*
* Returns nullopt if no such integer exists eg if gcd(x, m) > 1
*
* This algorithm is const time with respect to x, aside from its
* length. It also avoids leaking information about the modulus m,
* except that it does leak which of 3 categories the modulus is in:
*
*  - An odd integer
*  - A power of 2
*  - Some even number not a power of 2
*
* And if the modulus is even, it leaks the power of 2 which divides
* the modulus.
*
* @param x a positive integer less than m
* @param m a positive integer
*
* Throws Invalid_Argument if x or m are negative
*/
std::optional<BigInt> BOTAN_TEST_API inverse_mod_general(const BigInt& x, const BigInt& m);

/**
* Compute the inverse of x modulo a secret prime p
*
* This algorithm is constant time with respect to x and p, aside from
* leaking the length of p. (In particular it should not leak the
* length of x, if x is shorter)
*
* @param x a positive integer less than p
* @param p an odd prime
* @return y such that (x*y) % p == 1
*
* This always returns a result since any integer in [1,p)
* has an inverse modulo a prime p.
*
* This function assumes as a precondition that p truly is prime; the
* results may not be correct if this does not hold.
*
* Throws Invalid_Argument if x is less than or equal to zero,
* or if p is even or less than 3.
*/
BigInt BOTAN_TEST_API inverse_mod_secret_prime(const BigInt& x, const BigInt& p);

/**
* Compute the inverse of x modulo a public prime p
*
* This algorithm is constant time with respect to x. The prime
* p is assumed to be public.
*
* @param x a positive integer less than p
* @param p an odd prime
* @return y such that (x*y) % p == 1
*
* This always returns a result since any integer in [1,p)
* has an inverse modulo a prime p.
*
* This function assumes as a precondition that p truly is prime; the
* results may not be correct if this does not hold.
*
* Throws Invalid_Argument if x is less than or equal to zero,
* or if p is even or less than 3.
*/
BigInt BOTAN_TEST_API inverse_mod_public_prime(const BigInt& x, const BigInt& p);

/**
* Compute the inverse of x modulo a public RSA modulus n
*
* This algorithm is constant time with respect to x. The RSA
* modulus is assumed to be public.
*
* @param x a positive integer less than n
* @param n a RSA public modulus
* @return y such that (x*y) % n == 1
*
* This always returns a result since any integer in [1,n) has an inverse modulo
* a RSA public modulus n, unless you have happened to guess one of the factors
* at random. In the unlikely event of this occuring, Internal_Error will be thrown.
*/
BigInt inverse_mod_rsa_public_modulus(const BigInt& x, const BigInt& n);

/**
* Compute the RSA private exponent d
*
* This algorithm is constant time with respect to phi_n, p, and q,
* aside from leaking their lengths. It may leak the public exponent e.
*
* @param e the public exponent
* @param phi_n is lcm(p-1, q-1)
* @param p is the first secret prime
* @param q is the second secret prime
* @return d inverse of e modulo phi_n
*/
BigInt BOTAN_TEST_API compute_rsa_secret_exponent(const BigInt& e,
                                                  const BigInt& phi_n,
                                                  const BigInt& p,
                                                  const BigInt& q);

}  // namespace Botan

#endif
