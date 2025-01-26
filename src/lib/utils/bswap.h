/*
* Byte Swapping Operations
* (C) 1999-2011,2018 Jack Lloyd
* (C) 2007 Yves Jerschow
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* TODO: C++23: replace this entire implementation with std::byteswap
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BYTE_SWAP_H_
#define BOTAN_BYTE_SWAP_H_

#include <botan/types.h>

#include <botan/compiler.h>

namespace Botan {

/**
 * Swap the byte order of an unsigned integer
 */
template <std::unsigned_integral T>
   requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
inline constexpr T reverse_bytes(T x) {
   if constexpr(sizeof(T) == 1) {
      return x;
   } else if constexpr(sizeof(T) == 2) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap16)
      return static_cast<T>(__builtin_bswap16(x));
#else
      return static_cast<T>((x << 8) | (x >> 8));
#endif
   } else if constexpr(sizeof(T) == 4) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap32)
      return static_cast<T>(__builtin_bswap32(x));
#else
      // MSVC at least recognizes this as a bswap
      return static_cast<T>(((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8) |
                            ((x & 0xFF000000) >> 24));
#endif
   } else if constexpr(sizeof(T) == 8) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_bswap64)
      return static_cast<T>(__builtin_bswap64(x));
#else
      uint32_t hi = static_cast<uint32_t>(x >> 32);
      uint32_t lo = static_cast<uint32_t>(x);

      hi = reverse_bytes(hi);
      lo = reverse_bytes(lo);

      return (static_cast<T>(lo) << 32) | hi;
#endif
   }
}

}  // namespace Botan

#endif
