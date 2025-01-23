/*
* Division
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DIVISON_ALGORITHM_H_
#define BOTAN_DIVISON_ALGORITHM_H_

#include <botan/bigint.h>

namespace Botan {

/**
* BigInt Division
* @param x an integer
* @param y a non-zero integer
* @param q will be set to x / y
* @param r will be set to x % y
*/
BOTAN_TEST_API
void vartime_divide(const BigInt& x, const BigInt& y, BigInt& q, BigInt& r);

/**
* BigInt division, const time variant
*
* This runs with control flow independent of the values of x/y.
* Warning: the loop bounds still leak the sizes of x and y.
*
* @param x an integer
* @param y a non-zero integer
* @param q will be set to x / y
* @param r will be set to x % y
*/
BOTAN_TEST_API
void ct_divide(const BigInt& x, const BigInt& y, BigInt& q, BigInt& r);

/**
* BigInt division, const time variant, 2^k variant
*
* This runs with control flow independent of the value of y.
* This function leaks the value of k and the length of y.
* If k < bits(y) this returns zero
*
* @param k an integer
* @param y a positive integer
* @return q equal to 2**k / y
*/
BOTAN_TEST_API
BigInt ct_divide_pow2k(size_t k, const BigInt& y);

/**
* BigInt division, const time variant
*
* This runs with control flow independent of the values of x/y.
* Warning: the loop bounds still leak the sizes of x and y.
*
* @param x an integer
* @param y a non-zero integer
* @return x/y with remainder discarded
*/
inline BigInt ct_divide(const BigInt& x, const BigInt& y) {
   BigInt q, r;
   ct_divide(x, y, q, r);
   return q;
}

/**
* Constant time division
*
* This runs with control flow independent of the values of x/y.
* Warning: the loop bounds still leaks the size of x.
*
* @param x an integer
* @param y a non-zero integer
* @param q will be set to x / y
* @param r will be set to x % y
*/
BOTAN_TEST_API
void ct_divide_word(const BigInt& x, word y, BigInt& q, word& r);

/**
* Constant time division
*
* This runs with control flow independent of the values of x/y.
* Warning: the loop bounds still leaks the size of x.
*
* @param x an integer
* @param y a non-zero word
* @return quotient floor(x / y)
*/
inline BigInt ct_divide_word(const BigInt& x, word y) {
   BigInt q;
   word r;
   ct_divide_word(x, y, q, r);
   BOTAN_UNUSED(r);
   return q;
}

/**
* BigInt word modulo, const time variant
*
* This runs with control flow independent of the values of x/y.
* Warning: the loop bounds still leaks the size of x.
*
* @param x a positive integer
* @param y a non-zero word
* @return r the remainder of x divided by y
*/
BOTAN_TEST_API
word ct_mod_word(const BigInt& x, word y);

/**
* BigInt modulo, const time variant
*
* Using this function is (slightly) cheaper than calling ct_divide and
* using only the remainder.
*
* @param x a non-negative integer
* @param modulo a positive integer
* @return result x % modulo
*/
BOTAN_TEST_API
BigInt ct_modulo(const BigInt& x, const BigInt& modulo);

}  // namespace Botan

#endif
