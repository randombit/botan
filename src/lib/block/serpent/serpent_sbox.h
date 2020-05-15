/*
* Serpent SBox Expressions
* (C) 1999-2007,2013 Jack Lloyd
*
* The sbox expressions used here were discovered by Dag Arne Osvik and
* are described in his paper "Speeding Up Serpent".
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SERPENT_SBOX_H_
#define BOTAN_SERPENT_SBOX_H_

#include <botan/build.h>

template<typename T>
BOTAN_FORCE_INLINE void SBoxE0(T& B0, T& B1, T& B2, T& B3)
   {
   B3 ^= B0;
   T B4 = B1;
   B1 &= B3;
   B4 ^= B2;
   B1 ^= B0;
   B0 |= B3;
   B0 ^= B4;
   B4 ^= B3;
   B3 ^= B2;
   B2 |= B1;
   B2 ^= B4;
   B4 = ~B4;
   B4 |= B1;
   B1 ^= B3;
   B1 ^= B4;
   B3 |= B0;
   B1 ^= B3;
   B4 ^= B3;
   B3 = B0;
   B0 = B1;
   B1 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE1(T& B0, T& B1, T& B2, T& B3)
   {
   B0 = ~B0;
   B2 = ~B2;
   T B4 = B0;
   B0 &= B1;
   B2 ^= B0;
   B0 |= B3;
   B3 ^= B2;
   B1 ^= B0;
   B0 ^= B4;
   B4 |= B1;
   B1 ^= B3;
   B2 |= B0;
   B2 &= B4;
   B0 ^= B1;
   B1 &= B2;
   B1 ^= B0;
   B0 &= B2;
   B4 ^= B0;
   B0 = B2;
   B2 = B3;
   B3 = B1;
   B1 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE2(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B0;
   B0 &= B2;
   B0 ^= B3;
   B2 ^= B1;
   B2 ^= B0;
   B3 |= B4;
   B3 ^= B1;
   B4 ^= B2;
   B1 = B3;
   B3 |= B4;
   B3 ^= B0;
   B0 &= B1;
   B4 ^= B0;
   B1 ^= B3;
   B1 ^= B4;
   B0 = B2;
   B2 = B1;
   B1 = B3;
   B3 = ~B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE3(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B0;
   B0 |= B3;
   B3 ^= B1;
   B1 &= B4;
   B4 ^= B2;
   B2 ^= B3;
   B3 &= B0;
   B4 |= B1;
   B3 ^= B4;
   B0 ^= B1;
   B4 &= B0;
   B1 ^= B3;
   B4 ^= B2;
   B1 |= B0;
   B1 ^= B2;
   B0 ^= B3;
   B2 = B1;
   B1 |= B3;
   B0 ^= B1;
   B1 = B2;
   B2 = B3;
   B3 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE4(T& B0, T& B1, T& B2, T& B3)
   {
   B1 ^= B3;
   B3 = ~B3;
   B2 ^= B3;
   B3 ^= B0;
   T B4 = B1;
   B1 &= B3;
   B1 ^= B2;
   B4 ^= B3;
   B0 ^= B4;
   B2 &= B4;
   B2 ^= B0;
   B0 &= B1;
   B3 ^= B0;
   B4 |= B1;
   B4 ^= B0;
   B0 |= B3;
   B0 ^= B2;
   B2 &= B3;
   B0 = ~B0;
   B4 ^= B2;
   B2 = B0;
   B0 = B1;
   B1 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE5(T& B0, T& B1, T& B2, T& B3)
   {
   B0 ^= B1;
   B1 ^= B3;
   B3 = ~B3;
   T B4 = B1;
   B1 &= B0;
   B2 ^= B3;
   B1 ^= B2;
   B2 |= B4;
   B4 ^= B3;
   B3 &= B1;
   B3 ^= B0;
   B4 ^= B1;
   B4 ^= B2;
   B2 ^= B0;
   B0 &= B3;
   B2 = ~B2;
   B0 ^= B4;
   B4 |= B3;
   B4 ^= B2;
   B2 = B0;
   B0 = B1;
   B1 = B3;
   B3 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE6(T& B0, T& B1, T& B2, T& B3)
   {
   B2 = ~B2;
   T B4 = B3;
   B3 &= B0;
   B0 ^= B4;
   B3 ^= B2;
   B2 |= B4;
   B1 ^= B3;
   B2 ^= B0;
   B0 |= B1;
   B2 ^= B1;
   B4 ^= B0;
   B0 |= B3;
   B0 ^= B2;
   B4 ^= B3;
   B4 ^= B0;
   B3 = ~B3;
   B2 &= B4;
   B3 ^= B2;
   B2 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxE7(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B1;
   B1 |= B2;
   B1 ^= B3;
   B4 ^= B2;
   B2 ^= B1;
   B3 |= B4;
   B3 &= B0;
   B4 ^= B2;
   B3 ^= B1;
   B1 |= B4;
   B1 ^= B0;
   B0 |= B4;
   B0 ^= B2;
   B1 ^= B4;
   B2 ^= B1;
   B1 &= B0;
   B1 ^= B4;
   B2 = ~B2;
   B2 |= B0;
   B4 ^= B2;
   B2 = B1;
   B1 = B3;
   B3 = B0;
   B0 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD0(T& B0, T& B1, T& B2, T& B3)
   {
   B2 = ~B2;
   T B4 = B1;
   B1 |= B0;
   B4 = ~B4;
   B1 ^= B2;
   B2 |= B4;
   B1 ^= B3;
   B0 ^= B4;
   B2 ^= B0;
   B0 &= B3;
   B4 ^= B0;
   B0 |= B1;
   B0 ^= B2;
   B3 ^= B4;
   B2 ^= B1;
   B3 ^= B0;
   B3 ^= B1;
   B2 &= B3;
   B4 ^= B2;
   B2 = B1;
   B1 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD1(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B1;
   B1 ^= B3;
   B3 &= B1;
   B4 ^= B2;
   B3 ^= B0;
   B0 |= B1;
   B2 ^= B3;
   B0 ^= B4;
   B0 |= B2;
   B1 ^= B3;
   B0 ^= B1;
   B1 |= B3;
   B1 ^= B0;
   B4 = ~B4;
   B4 ^= B1;
   B1 |= B0;
   B1 ^= B0;
   B1 |= B4;
   B3 ^= B1;
   B1 = B0;
   B0 = B4;
   B4 = B2;
   B2 = B3;
   B3 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD2(T& B0, T& B1, T& B2, T& B3)
   {
   B2 ^= B3;
   B3 ^= B0;
   T B4 = B3;
   B3 &= B2;
   B3 ^= B1;
   B1 |= B2;
   B1 ^= B4;
   B4 &= B3;
   B2 ^= B3;
   B4 &= B0;
   B4 ^= B2;
   B2 &= B1;
   B2 |= B0;
   B3 = ~B3;
   B2 ^= B3;
   B0 ^= B3;
   B0 &= B1;
   B3 ^= B4;
   B3 ^= B0;
   B0 = B1;
   B1 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD3(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B2;
   B2 ^= B1;
   B0 ^= B2;
   B4 &= B2;
   B4 ^= B0;
   B0 &= B1;
   B1 ^= B3;
   B3 |= B4;
   B2 ^= B3;
   B0 ^= B3;
   B1 ^= B4;
   B3 &= B2;
   B3 ^= B1;
   B1 ^= B0;
   B1 |= B2;
   B0 ^= B3;
   B1 ^= B4;
   B0 ^= B1;
   B4 = B0;
   B0 = B2;
   B2 = B3;
   B3 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD4(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B2;
   B2 &= B3;
   B2 ^= B1;
   B1 |= B3;
   B1 &= B0;
   B4 ^= B2;
   B4 ^= B1;
   B1 &= B2;
   B0 = ~B0;
   B3 ^= B4;
   B1 ^= B3;
   B3 &= B0;
   B3 ^= B2;
   B0 ^= B1;
   B2 &= B0;
   B3 ^= B0;
   B2 ^= B4;
   B2 |= B3;
   B3 ^= B0;
   B2 ^= B1;
   B1 = B3;
   B3 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD5(T& B0, T& B1, T& B2, T& B3)
   {
   B1 = ~B1;
   T B4 = B3;
   B2 ^= B1;
   B3 |= B0;
   B3 ^= B2;
   B2 |= B1;
   B2 &= B0;
   B4 ^= B3;
   B2 ^= B4;
   B4 |= B0;
   B4 ^= B1;
   B1 &= B2;
   B1 ^= B3;
   B4 ^= B2;
   B3 &= B4;
   B4 ^= B1;
   B3 ^= B4;
   B4 = ~B4;
   B3 ^= B0;
   B0 = B1;
   B1 = B4;
   B4 = B3;
   B3 = B2;
   B2 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD6(T& B0, T& B1, T& B2, T& B3)
   {
   B0 ^= B2;
   T B4 = B2;
   B2 &= B0;
   B4 ^= B3;
   B2 = ~B2;
   B3 ^= B1;
   B2 ^= B3;
   B4 |= B0;
   B0 ^= B2;
   B3 ^= B4;
   B4 ^= B1;
   B1 &= B3;
   B1 ^= B0;
   B0 ^= B3;
   B0 |= B2;
   B3 ^= B1;
   B4 ^= B0;
   B0 = B1;
   B1 = B2;
   B2 = B4;
   }

template<typename T>
BOTAN_FORCE_INLINE void SBoxD7(T& B0, T& B1, T& B2, T& B3)
   {
   T B4 = B2;
   B2 ^= B0;
   B0 &= B3;
   B4 |= B3;
   B2 = ~B2;
   B3 ^= B1;
   B1 |= B0;
   B0 ^= B2;
   B2 &= B4;
   B3 &= B4;
   B1 ^= B2;
   B2 ^= B0;
   B0 |= B2;
   B4 ^= B1;
   B0 ^= B3;
   B3 ^= B4;
   B4 |= B0;
   B3 ^= B2;
   B4 ^= B2;
   B2 = B1;
   B1 = B0;
   B0 = B3;
   B3 = B4;
   }

#endif
