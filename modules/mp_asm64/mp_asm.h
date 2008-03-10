/*************************************************
* MPI Multiply-Add Core Header File              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_MADD_H__
#define BOTAN_MP_MADD_H__

#include <botan/mp_types.h>

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
   asm("dmultu %2,%3" : "=h" (z0), "=l" (z1) : "r" (a), "r" (b)); \
} while(0);

#else

#include <botan/mp_core.h>

#define BOTAN_WORD_MUL(a,b,z1,z0) \
   do { bigint_wordmul(a, b, &z1, &z0); } while(0);

#endif

namespace Botan {

/*************************************************
* Word Multiply/Add                              *
*************************************************/
inline word word_madd2(word a, word b, word* c)
   {
   word z0 = 0, z1 = 0;

   BOTAN_WORD_MUL(a, b, z1, z0);

   z1 += *c; if(z1 < *c) z0++;

   *c = z0;
   return z1;
   }

/*************************************************
* Word Multiply/Add                              *
*************************************************/
inline word word_madd3(word a, word b, word c, word* d)
   {
   word z0 = 0, z1 = 0;

   BOTAN_WORD_MUL(a, b, z1, z0);

   z1 += c; if(z1 < c) z0++;
   z1 += *d; if(z1 < *d) z0++;

   *d = z0;
   return z1;
   }

}

#endif
