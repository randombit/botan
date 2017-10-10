/*
* Word Rotation Operations
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WORD_ROTATE_H_
#define BOTAN_WORD_ROTATE_H_

#include <botan/types.h>

namespace Botan {

/**
* Bit rotation left
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated left by rot bits
*/
template<typename T> inline T rotate_left(T input, uint8_t rot)
   {
   rot %= 8 * sizeof(T);
   return (rot == 0) ? input : static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot)));;
   }

/**
* Bit rotation right
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated right by rot bits
*/
template<typename T> inline T rotate_right(T input, uint8_t rot)
   {
   rot %= 8 * sizeof(T);
   return (rot == 0) ? input : static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot)));
   }

#if BOTAN_USE_GCC_INLINE_ASM

#if defined(BOTAN_TARGET_ARCH_IS_X86_64) || defined(BOTAN_TARGET_ARCH_IS_X86_32)

template<>
inline uint32_t rotate_left(uint32_t input, uint8_t rot)
   {
   asm("roll %1,%0" : "+r" (input) : "c" (rot));
   return input;
   }

template<>
inline uint32_t rotate_right(uint32_t input, uint8_t rot)
   {
   asm("rorl %1,%0" : "+r" (input) : "c" (rot));
   return input;
   }

#endif

#endif

}

#endif
