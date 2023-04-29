/*
* 64x64->128 bit multiply operation
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_MUL128_H_
#define BOTAN_UTIL_MUL128_H_

#include <botan/types.h>

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)
  #include <intrin.h>
#endif

namespace Botan {

#if defined(__SIZEOF_INT128__) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)
   #define BOTAN_TARGET_HAS_NATIVE_UINT128

   // GCC complains if this isn't marked with __extension__
   __extension__ typedef unsigned __int128 uint128_t;
#endif

/**
* Perform a 64x64->128 bit multiplication
*/
inline void mul64x64_128(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi)
   {
#if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)

   const uint128_t r = static_cast<uint128_t>(a) * b;
   *hi = (r >> 64) & 0xFFFFFFFFFFFFFFFF;
   *lo = (r      ) & 0xFFFFFFFFFFFFFFFF;

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_ARCH_IS_X86_64)
    *lo = _umul128(a, b, hi);

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_ARCH_IS_ARM64)
    *lo = a * b;
    *hi = __umulh(a, b);

#elif defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_ARCH_IS_X86_64)
   asm("mulq %3"
       : "=d" (*hi), "=a" (*lo)
       : "a" (a), "rm" (b)
       : "cc");

#elif defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_ARCH_IS_PPC64)
   asm("mulhdu %0,%1,%2"
       : "=r" (*hi)
       : "r" (a), "r" (b)
       : "cc");
   *lo = a * b;

#else

   /*
   * Do a 64x64->128 multiply using four 32x32->64 multiplies plus
   * some adds and shifts. Last resort for CPUs like UltraSPARC (with
   * 64-bit registers/ALU, but no 64x64->128 multiply) or 32-bit CPUs.
   */
   const size_t HWORD_BITS = 32;
   const uint32_t HWORD_MASK = 0xFFFFFFFF;

   const uint32_t a_hi = (a >> HWORD_BITS);
   const uint32_t a_lo = (a  & HWORD_MASK);
   const uint32_t b_hi = (b >> HWORD_BITS);
   const uint32_t b_lo = (b  & HWORD_MASK);

   uint64_t x0 = static_cast<uint64_t>(a_hi) * b_hi;
   uint64_t x1 = static_cast<uint64_t>(a_lo) * b_hi;
   uint64_t x2 = static_cast<uint64_t>(a_hi) * b_lo;
   uint64_t x3 = static_cast<uint64_t>(a_lo) * b_lo;

   // this cannot overflow as (2^32-1)^2 + 2^32-1 < 2^64-1
   x2 += x3 >> HWORD_BITS;

   // this one can overflow
   x2 += x1;

   // propagate the carry if any
   x0 += static_cast<uint64_t>(static_cast<bool>(x2 < x1)) << HWORD_BITS;

   *hi = x0 + (x2 >> HWORD_BITS);
   *lo  = ((x2 & HWORD_MASK) << HWORD_BITS) + (x3 & HWORD_MASK);
#endif
   }

}

#endif
