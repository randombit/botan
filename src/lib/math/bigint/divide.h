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
* BigInt division, const time variant
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
