/*************************************************
* Lowest Level MPI Algorithms Header File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_ASM_H__
#define BOTAN_MP_ASM_H__

#include <botan/mp_types.h>

#if (BOTAN_MP_WORD_BITS == 8)
  typedef Botan::u16bit dword;
#elif (BOTAN_MP_WORD_BITS == 16)
  typedef Botan::u32bit dword;
#elif (BOTAN_MP_WORD_BITS == 32)
  typedef Botan::u64bit dword;
#elif (BOTAN_MP_WORD_BITS == 64)
  #error BOTAN_MP_WORD_BITS can be 64 only with assembly support
#else
  #error BOTAN_MP_WORD_BITS must be 8, 16, 32, or 64
#endif

namespace Botan {

extern "C" {

/*************************************************
* Word Multiply/Add                              *
*************************************************/
inline word word_madd2(word a, word b, word c, word* carry)
   {
   dword z = (dword)a * b + c;
   *carry = (word)(z >> BOTAN_MP_WORD_BITS);
   return (word)z;
   }

/*************************************************
* Word Multiply/Add                              *
*************************************************/
inline word word_madd3(word a, word b, word c, word d, word* carry)
   {
   dword z = (dword)a * b + c + d;
   *carry = (word)(z >> BOTAN_MP_WORD_BITS);
   return (word)z;
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd(word* w2, word* w1, word* w0, word a, word b)
   {
   *w0 = word_madd2(a, b, *w0, &a);
   *w1 += a;
   *w2 += (*w1 < a) ? 1 : 0;
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd_2(word* w2, word* w1, word* w0, word a, word b)
   {
   a = word_madd2(a, b, 0, &b);

   *w0 += a;
   *w1 += b + ((*w0 < a) ? 1 : 0);
   *w2 += (*w1 < b) ? 1 : 0;

   *w0 += a;
   *w1 += b + ((*w0 < a) ? 1 : 0);
   *w2 += (*w1 < b) ? 1 : 0;
   }

}

}

#endif
