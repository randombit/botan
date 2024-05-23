/*
* Bit/Word Operations
* (C) 1999-2008 Jack Lloyd
* (C) Copyright Projet SECRET, INRIA, Rocquencourt
* (C) Bhaskar Biswas and  Nicolas Sendrier
* (C) 2014 cryptosource GmbH
* (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BIT_OPS_H_
#define BOTAN_BIT_OPS_H_

#include <botan/types.h>

namespace Botan {

/**
* If top bit of arg is set, return ~0. Otherwise return 0.
*/
template <typename T>
inline constexpr T expand_top_bit(T a)
   requires(std::is_integral<T>::value)
{
   return static_cast<T>(0) - (a >> (sizeof(T) * 8 - 1));
}

/**
* If arg is zero, return ~0. Otherwise return 0
*/
template <typename T>
inline constexpr T ct_is_zero(T x)
   requires(std::is_integral<T>::value)
{
   return expand_top_bit<T>(~x & (x - 1));
}

/**
* Power of 2 test. T should be an unsigned integer type
* @param arg an integer value
* @return true iff arg is 2^n for some n > 0
*/
template <typename T>
inline constexpr bool is_power_of_2(T arg)
   requires(std::is_unsigned<T>::value)
{
   return (arg != 0) && (arg != 1) && ((arg & static_cast<T>(arg - 1)) == 0);
}

/**
* Return the index of the highest set bit
* T is an unsigned integer type
* @param n an integer value
* @return index of the highest set bit in n
*/
template <typename T>
inline constexpr size_t high_bit(T n)
   requires(std::is_unsigned<T>::value)
{
   size_t hb = 0;

   for(size_t s = 8 * sizeof(T) / 2; s > 0; s /= 2) {
      const size_t z = s * ((~ct_is_zero(n >> s)) & 1);
      hb += z;
      n >>= z;
   }

   hb += n;

   return hb;
}

/**
* Return the number of significant bytes in n
* @param n an integer value
* @return number of significant bytes in n
*/
template <typename T>
inline constexpr size_t significant_bytes(T n)
   requires(std::is_integral<T>::value)
{
   size_t b = 0;

   for(size_t s = 8 * sizeof(n) / 2; s >= 8; s /= 2) {
      const size_t z = s * (~ct_is_zero(n >> s) & 1);
      b += z / 8;
      n >>= z;
   }

   b += (n != 0);

   return b;
}

/**
* Count the trailing zero bits in n
* @param n an integer value
* @return maximum x st 2^x divides n
*/
template <typename T>
inline constexpr size_t ctz(T n)
   requires(std::is_integral<T>::value)
{
   /*
   * If n == 0 then this function will compute 8*sizeof(T)-1, so
   * initialize lb to 1 if n == 0 to produce the expected result.
   */
   size_t lb = ct_is_zero(n) & 1;

   for(size_t s = 8 * sizeof(T) / 2; s > 0; s /= 2) {
      const T mask = (static_cast<T>(1) << s) - 1;
      const size_t z = s * (ct_is_zero(n & mask) & 1);
      lb += z;
      n >>= z;
   }

   return lb;
}

template <typename T>
constexpr uint8_t ceil_log2(T x)
   requires(std::is_integral<T>::value && sizeof(T) < 32)
{
   if(x >> (sizeof(T) * 8 - 1)) {
      return sizeof(T) * 8;
   }

   uint8_t result = 0;
   T compare = 1;

   while(compare < x) {
      compare <<= 1;
      result++;
   }

   return result;
}

/**
 * Ceil of an unsigned integer division. @p b must not be zero.
 *
 * @param a divident
 * @param b divisor
 *
 * @returns ceil(a/b)
 */
template <std::unsigned_integral T>
inline constexpr T ceil_division(T a, T b) {
   return (a + b - 1) / b;
}

/**
 * Return the number of bytes necessary to contain @p bits bits.
 */
template <typename T>
inline constexpr T ceil_tobytes(T bits)
   requires(std::is_integral<T>::value)
{
   return (bits + 7) / 8;
}

// Potentially variable time ctz used for OCB
inline constexpr size_t var_ctz32(uint32_t n) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_ctz)
   if(n == 0) {
      return 32;
   }
   return __builtin_ctz(n);
#else
   return ctz<uint32_t>(n);
#endif
}

template <typename T>
inline constexpr T bit_permute_step(T x, T mask, size_t shift) {
   /*
   See https://reflectionsonsecurity.wordpress.com/2014/05/11/efficient-bit-permutation-using-delta-swaps/
   and http://programming.sirrida.de/bit_perm.html
   */
   const T swap = ((x >> shift) ^ x) & mask;
   return (x ^ swap) ^ (swap << shift);
}

template <typename T>
inline constexpr void swap_bits(T& x, T& y, T mask, size_t shift) {
   const T swap = ((x >> shift) ^ y) & mask;
   x ^= swap << shift;
   y ^= swap;
}

template <typename T>
inline constexpr T choose(T mask, T a, T b) {
   //return (mask & a) | (~mask & b);
   return (b ^ (mask & (a ^ b)));
}

template <typename T>
inline constexpr T majority(T a, T b, T c) {
   /*
   Considering each bit of a, b, c individually

   If a xor b is set, then c is the deciding vote.

   If a xor b is not set then either a and b are both set or both unset.
   In either case the value of c doesn't matter, and examining b (or a)
   allows us to determine which case we are in.
   */
   return choose(a ^ b, c, b);
}

}  // namespace Botan

#endif
