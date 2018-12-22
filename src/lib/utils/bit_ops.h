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
template<typename T>
inline T expand_top_bit(T a)
   {
   return static_cast<T>(0) - (a >> (sizeof(T)*8-1));
   }

/**
* If arg is zero, return ~0. Otherwise return 0
*/
template<typename T>
inline T ct_is_zero(T x)
   {
   return expand_top_bit<T>(~x & (x - 1));
   }

/**
* Power of 2 test. T should be an unsigned integer type
* @param arg an integer value
* @return true iff arg is 2^n for some n > 0
*/
template<typename T>
inline constexpr bool is_power_of_2(T arg)
   {
   return ((arg != 0 && arg != 1) && ((arg & static_cast<T>(arg-1)) == 0));
   }

/**
* Return the index of the highest set bit
* T is an unsigned integer type
* @param n an integer value
* @return index of the highest set bit in n
*/
template<typename T>
inline size_t high_bit(T n)
   {
   size_t hb = 0;

   for(size_t s = 8*sizeof(T) / 2; s > 0; s /= 2)
      {
      /*
      * The != 0 expression is not necessarily going to be const time,
      * it will depend on the compiler and arch. GCC compiles this
      * function to straight line code on x86-64, Aarch64 and ARM.
      */
      const size_t z = s * ((n >> s) != 0);
      hb += z;
      n >>= z;
      }

   hb += n;

   return hb;
   }

/**
* Return the index of the lowest set bit
* T is an unsigned integer type
* @param n an integer value
* @return index of the lowest set bit in n
*/
template<typename T>
inline size_t low_bit(T n)
   {
   for(size_t i = 0; i != 8*sizeof(T); ++i)
      if((n >> i) & 0x01)
         return (i + 1);
   return 0;
   }

/**
* Return the number of significant bytes in n
* @param n an integer value
* @return number of significant bytes in n
*/
template<typename T>
inline size_t significant_bytes(T n)
   {
   for(size_t i = 0; i != sizeof(T); ++i)
      if(get_byte(i, n))
         return sizeof(T)-i;
   return 0;
   }

/**
* Count the trailing zero bits in n
* @param n an integer value
* @return maximum x st 2^x divides n
*/
template<typename T>
inline size_t ctz(T n)
   {
   /*
   * If n == 0 then this function will compute 8*sizeof(T)-1, so
   * initialize lb to 1 if n == 0 to produce the expected result.
   */
   size_t lb = (n == 0);

   for(size_t s = 8*sizeof(T) / 2; s > 0; s /= 2)
      {
      const T mask = (static_cast<T>(1) << s) - 1;
      const T n_bits = (n & mask) == 0;
      lb += s * n_bits;
      n >>= s * n_bits;
      }

   return lb;
   }

template<typename T>
size_t ceil_log2(T x)
   {
   if(x >> (sizeof(T)*8-1))
      return sizeof(T)*8;

   size_t result = 0;
   T compare = 1;

   while(compare < x)
      {
      compare <<= 1;
      result++;
      }

   return result;
   }

#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)

template<>
inline size_t ctz(uint32_t n)
   {
   if(n == 0)
      return 32;
   return __builtin_ctz(n);
   }

template<>
inline size_t ctz(uint64_t n)
   {
   if(n == 0)
      return 64;
   return __builtin_ctzll(n);
   }

#endif

}

#endif
