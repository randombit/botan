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

#include <botan/compiler.h>
#include <botan/internal/bswap.h>

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
inline constexpr T floor_log2(T n)
   requires(std::is_unsigned<T>::value)
{
   BOTAN_ARG_CHECK(n != 0, "log2(0) is not defined");
   return static_cast<T>(high_bit(n) - 1);
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

/**
 * @returns the reversed bits in @p b.
 */
template <std::unsigned_integral T>
constexpr T ct_reverse_bits(T b) {
   auto extend = [](uint8_t m) -> T {
      T mask = 0;
      for(size_t i = 0; i < sizeof(T); ++i) {
         mask |= T(m) << i * 8;
      }
      return mask;
   };

   // First reverse bits in each byte...
   // From: https://stackoverflow.com/a/2602885
   b = (b & extend(0xF0)) >> 4 | (b & extend(0x0F)) << 4;
   b = (b & extend(0xCC)) >> 2 | (b & extend(0x33)) << 2;
   b = (b & extend(0xAA)) >> 1 | (b & extend(0x55)) << 1;

   // ... then swap the bytes
   return reverse_bytes(b);
}

/**
 * Calculates the number of 1-bits in an unsigned integer in constant-time.
 * This operation is also known as "population count" or hamming weight.
 *
 * Modern compilers will recognize this pattern and replace it by a hardware
 * instruction, if available. This is the SWAR (SIMD within a register)
 * algorithm. See: https://nimrod.blog/posts/algorithms-behind-popcount/#swar-algorithm
 *
 * Note: C++20 provides std::popcount(), but there's no guarantee that this
 *       is implemented in constant-time.
 *
 * @param x an unsigned integer
 * @returns the number of 1-bits in the provided value
 */
template <std::unsigned_integral T>
inline constexpr uint8_t ct_popcount(T x) {
   constexpr size_t s = sizeof(T);
   static_assert(s <= 8, "T is not a suitable unsigned integer value");
   if constexpr(s == 8) {
      x = x - ((x >> 1) & 0x5555555555555555);
      x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333);
      x = (x + (x >> 4)) & 0xF0F0F0F0F0F0F0F;
      return (x * 0x101010101010101) >> 56;
   } else if constexpr(s == 4) {
      x = x - ((x >> 1) & 0x55555555);
      x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
      x = (x + (x >> 4)) & 0x0F0F0F0F;
      return (x * 0x01010101) >> 24;
   } else {
      // s < 4
      return ct_popcount(static_cast<uint32_t>(x));
   }
}

}  // namespace Botan

#endif
