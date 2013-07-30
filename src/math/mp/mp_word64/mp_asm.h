/*
* MPI Multiply-Add Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MP_MADD_H__
#define BOTAN_MP_MADD_H__

#include <botan/mp_types.h>
#include <botan/internal/mul128.h>

namespace Botan {

#if (BOTAN_MP_WORD_BITS != 64)
   #error The mp_word64 module requires that BOTAN_MP_WORD_BITS == 64
#endif

/*
* Word Multiply/Add
*/
inline word word_madd2(word a, word b, word* c)
   {
   word z0 = 0, z1 = 0;

   mul64x64_128(a, b, &z1, &z0);

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

   mul64x64_128(a, b, &z1, &z0);

   z1 += c;
   z0 += (z1 < c);

   z1 += *d;
   z0 += (z1 < *d);

   *d = z0;
   return z1;
   }

}

#endif
