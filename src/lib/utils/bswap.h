/*
* Byte Swapping Operations
* (C) 1999-2011,2018 Jack Lloyd
* (C) 2007 Yves Jerschow
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BYTE_SWAP_H_
#define BOTAN_BYTE_SWAP_H_

#include <botan/types.h>

namespace Botan {

/**
* Swap a 16 bit integer
*/
inline constexpr uint16_t reverse_bytes(uint16_t x) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap16)
   return __builtin_bswap16(x);
#else
   return static_cast<uint16_t>((x << 8) | (x >> 8));
#endif
}

/**
* Swap a 32 bit integer
*
* We cannot use MSVC's _byteswap_ulong because it does not consider
* the builtin to be constexpr.
*/
inline constexpr uint32_t reverse_bytes(uint32_t x) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap32)
   return __builtin_bswap32(x);
#else
   // MSVC at least recognizes this as a bswap
   return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
#endif
}

/**
* Swap a 64 bit integer
*
* We cannot use MSVC's _byteswap_uint64 because it does not consider
* the builtin to be constexpr.
*/
inline constexpr uint64_t reverse_bytes(uint64_t x) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap64)
   return __builtin_bswap64(x);
#else
   uint32_t hi = static_cast<uint32_t>(x >> 32);
   uint32_t lo = static_cast<uint32_t>(x);

   hi = reverse_bytes(hi);
   lo = reverse_bytes(lo);

   return (static_cast<uint64_t>(lo) << 32) | hi;
#endif
}

}  // namespace Botan

#endif
