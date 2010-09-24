/*
* Multiply-Add for 64-bit MSVC
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MP_ASM_H__
#define BOTAN_MP_ASM_H__

#include <botan/mp_types.h>
#include <intrin.h>

#if (BOTAN_MP_WORD_BITS != 64)
   #error The mp_msvc64 module requires that BOTAN_MP_WORD_BITS == 64
#endif

#pragma intrinsic(_umul128)

namespace Botan {

extern "C" {

/*
* Word Multiply
*/
inline word word_madd2(word a, word b, word* c)
   {
   word hi, lo;
   lo = _umul128(a, b, &hi);

   lo += *c;
   hi += (lo < *c); // carry?

   *c = hi;
   return lo;
   }

/*
* Word Multiply/Add
*/
inline word word_madd3(word a, word b, word c, word* d)
   {
   word hi, lo;
   lo = _umul128(a, b, &hi);

   lo += c;
   hi += (lo < c); // carry?

   lo += *d;
   hi += (lo < *d); // carry?

   *d = hi;
   return lo;
   }

}

}

#endif
