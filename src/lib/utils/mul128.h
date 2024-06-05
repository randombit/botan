/*
* 64x64->128 bit multiply operation
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_MUL128_H_
#define BOTAN_UTIL_MUL128_H_

#include <botan/types.h>
#include <type_traits>

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)
   #include <intrin.h>
#endif

namespace Botan {

/**
* Perform a 64x64->128 bit multiplication
*/
constexpr inline void mul64x64_128(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi) {
   if(!std::is_constant_evaluated()) {
#if defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_ARCH_IS_X86_64)
      *lo = _umul128(a, b, hi);
      return;

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_ARCH_IS_ARM64)
      *lo = a * b;
      *hi = __umulh(a, b);
      return;
#endif
   }

#if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
   const uint128_t r = static_cast<uint128_t>(a) * b;
   *hi = (r >> 64) & 0xFFFFFFFFFFFFFFFF;
   *lo = (r) & 0xFFFFFFFFFFFFFFFF;
#else

   /*
   * Do a 64x64->128 multiply using four 32x32->64 multiplies plus
   * some adds and shifts.
   */
   const size_t HWORD_BITS = 32;
   const uint32_t HWORD_MASK = 0xFFFFFFFF;

   const uint32_t a_hi = (a >> HWORD_BITS);
   const uint32_t a_lo = (a & HWORD_MASK);
   const uint32_t b_hi = (b >> HWORD_BITS);
   const uint32_t b_lo = (b & HWORD_MASK);

   const uint64_t x0 = static_cast<uint64_t>(a_hi) * b_hi;
   const uint64_t x1 = static_cast<uint64_t>(a_lo) * b_hi;
   const uint64_t x2 = static_cast<uint64_t>(a_hi) * b_lo;
   const uint64_t x3 = static_cast<uint64_t>(a_lo) * b_lo;

   // this cannot overflow as (2^32-1)^2 + 2^32-1 + 2^32-1 = 2^64-1
   const uint64_t middle = x2 + (x3 >> HWORD_BITS) + (x1 & HWORD_MASK);

   // likewise these cannot overflow
   *hi = x0 + (middle >> HWORD_BITS) + (x1 >> HWORD_BITS);
   *lo = (middle << HWORD_BITS) + (x3 & HWORD_MASK);
#endif
}

}  // namespace Botan

#endif
