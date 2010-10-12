/*
* MPI Multiply-Add Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MP_MADD_H__
#define BOTAN_MP_MADD_H__

#include <botan/mp_types.h>

namespace Botan {

#if (BOTAN_MP_WORD_BITS != 64)
   #error The mp_asm64 module requires that BOTAN_MP_WORD_BITS == 64
#endif

#if defined(BOTAN_TARGET_ARCH_IS_ALPHA)

#define BOTAN_WORD_MUL(a,b,z1,z0) do {                   \
   asm("umulh %1,%2,%0" : "=r" (z0) : "r" (a), "r" (b)); \
   z1 = a * b;                                           \
} while(0);

#elif defined(BOTAN_TARGET_ARCH_IS_IA64)

#define BOTAN_WORD_MUL(a,b,z1,z0) do {                     \
   asm("xmpy.hu %0=%1,%2" : "=f" (z0) : "f" (a), "f" (b)); \
   z1 = a * b;                                             \
} while(0);

#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)

#define BOTAN_WORD_MUL(a,b,z1,z0) do {                           \
   asm("mulhdu %0,%1,%2" : "=r" (z0) : "r" (a), "r" (b) : "cc"); \
   z1 = a * b;                                                   \
} while(0);

#elif defined(BOTAN_TARGET_ARCH_IS_MIPS64)

#define BOTAN_WORD_MUL(a,b,z1,z0) do {                            \
   typedef unsigned int uint128_t __attribute__((mode(TI)));      \
   uint128_t r = (uint128_t)a * b;                                \
   z0 = (r >> 64) & 0xFFFFFFFFFFFFFFFF;                           \
   z1 = (r      ) & 0xFFFFFFFFFFFFFFFF;                           \
} while(0);

#else

// Do a 64x64->128 multiply using four 64x64->64 multiplies
// plus some adds and shifts. Last resort for CPUs like UltraSPARC,
// with 64-bit registers/ALU, but no 64x64->128 multiply.
inline void bigint_2word_mul(word a, word b, word* z1, word* z0)
   {
   const size_t MP_HWORD_BITS = BOTAN_MP_WORD_BITS / 2;
   const word MP_HWORD_MASK = ((word)1 << MP_HWORD_BITS) - 1;

   const word a_hi = (a >> MP_HWORD_BITS);
   const word a_lo = (a & MP_HWORD_MASK);
   const word b_hi = (b >> MP_HWORD_BITS);
   const word b_lo = (b & MP_HWORD_MASK);

   word x0 = a_hi * b_hi;
   word x1 = a_lo * b_hi;
   word x2 = a_hi * b_lo;
   word x3 = a_lo * b_lo;

   x2 += x3 >> (MP_HWORD_BITS);
   x2 += x1;

   if(x2 < x1) // timing channel
      x0 += ((word)1 << MP_HWORD_BITS);

   *z0 = x0 + (x2 >> MP_HWORD_BITS);
   *z1 = ((x2 & MP_HWORD_MASK) << MP_HWORD_BITS) + (x3 & MP_HWORD_MASK);
   }

#define BOTAN_WORD_MUL(a,b,z1,z0) bigint_2word_mul(a, b, &z1, &z0)

#endif

/*
* Word Multiply/Add
*/
inline word word_madd2(word a, word b, word* c)
   {
   word z0 = 0, z1 = 0;

   BOTAN_WORD_MUL(a, b, z1, z0);

   z1 += *c;
   z0 += (z1 < *c);

   *c = z0;
   return z1;
   }

/*
* Word Multiply/Add
*/
inline word word_madd3(word a, word b, word c, word* d)
   {
   word z0 = 0, z1 = 0;

   BOTAN_WORD_MUL(a, b, z1, z0);

   z1 += c;
   z0 += (z1 < c);

   z1 += *d;
   z0 += (z1 < *d);

   *d = z0;
   return z1;
   }

}

#endif
