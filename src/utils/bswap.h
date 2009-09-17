/*
* Byte Swapping Operations
* (C) 1999-2008 Jack Lloyd
* (C) 2007 Yves Jerschow
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BYTE_SWAP_H__
#define BOTAN_BYTE_SWAP_H__

#include <botan/types.h>
#include <botan/rotate.h>

namespace Botan {

/*
* Byte Swapping Functions
*/
inline u16bit reverse_bytes(u16bit input)
   {
   return rotate_left(input, 8);
   }

inline u32bit reverse_bytes(u32bit input)
   {
#if BOTAN_USE_GCC_INLINE_ASM && \
    (defined(BOTAN_TARGET_ARCH_IS_IA32) || defined(BOTAN_TARGET_ARCH_IS_AMD64))

   /* GCC-style inline assembly for x86 or x86-64 */
   asm("bswapl %0" : "=r" (input) : "0" (input));
   return input;

#elif defined(_MSC_VER) && defined(BOTAN_TARGET_ARCH_IS_IA32)
   /* Visual C++ inline asm for 32-bit x86, by Yves Jerschow */
   __asm mov eax, input;
   __asm bswap eax;

#else
   /* Generic implementation */
   input = ((input & 0xFF00FF00) >> 8) | ((input & 0x00FF00FF) << 8);
   return rotate_left(input, 16);
#endif
   }

inline u64bit reverse_bytes(u64bit input)
   {
#if BOTAN_USE_GCC_INLINE_ASM && defined(BOTAN_TARGET_ARCH_IS_AMD64)
   asm("bswapq %0" : "=r" (input) : "0" (input));
   return input;
#else
   u32bit hi = ((input >> 40) & 0x00FF00FF) | ((input >> 24) & 0xFF00FF00);
   u32bit lo = ((input & 0xFF00FF00) >> 8) | ((input & 0x00FF00FF) << 8);
   hi = (hi << 16) | (hi >> 16);
   lo = (lo << 16) | (lo >> 16);
   return (static_cast<u64bit>(lo) << 32) | hi;
#endif
   }

}

#endif
