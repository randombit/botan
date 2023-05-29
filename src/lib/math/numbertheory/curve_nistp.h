/*
* Arithmetic operations specialized for NIST ECC primes
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_NIST_PRIMES_H_
#define BOTAN_NIST_PRIMES_H_

#include <botan/bigint.h>

namespace Botan {

/*
* NIST Prime reduction functions.
*
* Reduces the value in place
*
* ws is a workspace function which is used as a temporary,
* and will be resized as needed.
*/

/**
* Return the P-521 prime
*/
BOTAN_TEST_API const BigInt& prime_p521();

/**
* Reduce an input modulo P-521
*
* Input value x must be between 0 and p**2
*/
BOTAN_TEST_API void redc_p521(BigInt& x, secure_vector<word>& ws);

/**
* Return the P-384 prime
*/
BOTAN_TEST_API const BigInt& prime_p384();

/**
* Reduce an input modulo P-384
*
* Input value x must be between 0 and p**2
*/
BOTAN_TEST_API void redc_p384(BigInt& x, secure_vector<word>& ws);

/**
* Return the P-256 prime
*/
BOTAN_TEST_API const BigInt& prime_p256();

/**
* Reduce an input modulo P-256
*
* Input value x must be between 0 and p**2
*/
BOTAN_TEST_API void redc_p256(BigInt& x, secure_vector<word>& ws);

/**
* Return the P-224 prime
*/
BOTAN_TEST_API const BigInt& prime_p224();

/**
* Reduce an input modulo P-224
*
* Input value x must be between 0 and p**2
*/
BOTAN_TEST_API void redc_p224(BigInt& x, secure_vector<word>& ws);

/**
* Return the P-192 prime
*/
BOTAN_TEST_API const BigInt& prime_p192();

/**
* Reduce an input modulo P-192
*
* Input value x must be between 0 and p**2
*/
BOTAN_TEST_API void redc_p192(BigInt& x, secure_vector<word>& ws);

}  // namespace Botan

#endif
