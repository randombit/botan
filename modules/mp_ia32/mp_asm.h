/*************************************************
* Lowest Level MPI Algorithms Header File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_ASM_H__
#define BOTAN_MP_ASM_H__

#include <botan/mp_types.h>

#if (BOTAN_MP_WORD_BITS != 32)
   #error The mp_ia32 module requires that BOTAN_MP_WORD_BITS == 32
#endif

namespace Botan {

extern "C" {

/*************************************************
* Word Multiply                                  *
*************************************************/
inline word word_madd2(word a, word b, word c, word* carry)
   {
   asm(
      "mull %1\n\t"        // a (eax) * b (anywhere) -> edx:eax
      "addl %5,%0\n\t"     // add c to low word (eax)
      "adcl $0,%2"         // add carry from previous to high word (edx)
      : "=a"(a), "=rm"(b), "=&d"(*carry)
      : "0"(a), "1"(b), "g"(c) : "cc");

   return a;
   }

/*************************************************
* Word Multiply/Add                              *
*************************************************/
inline word word_madd3(word a, word b, word c, word d, word* carry)
   {
   asm(
      "mull %1\n\t"        // a (eax) * b (anywhere) -> edx:eax
      "addl %5,%0\n\t"     // add c to low word (eax)
      "adcl $0,%2\n\t"     // add carry from previous add to high word (edx)
      "addl %6,%0\n\t"     // add d to low word (eax)
      "adcl $0,%2"         // add carry from previous add to high word (edx)
      : "=a"(a), "=rm"(b), "=&d"(*carry)
      : "0"(a), "1"(b), "g"(c), "g"(d) : "cc");

   return a;
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd(word* w2, word* w1, word* w0, word x, word y)
   {
   asm(
      "mull %[y]\n\t"      // a (eax) * b (anywhere) -> edx:eax
      "addl %3,%[w0]\n\t"  // add c to low word (eax)
      "adcl %4,%[w1]\n\t"  // add carry from previous add to high word (edx)
      "adcl $0,%[w2]\n\t"  // add carry from previous add to high word (edx)
      : [w0]"=r"(*w0), [w1]"=r"(*w1), [w2]"=r"(*w2)
      : "a"(x), [y]"d"(y), "0"(*w0), "1"(*w1), "2"(*w2)
      : "cc");
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd_2(word* w2, word* w1, word* w0, word x, word y)
   {
   asm(
      "mull %[y]\n\t"      // a (eax) * b (anywhere) -> edx:eax
      "addl %3,%[w0]\n\t"  // add c to low word (eax)
      "adcl %4,%[w1]\n\t"  // add carry from previous add to high word (edx)
      "adcl $0,%[w2]\n\t"  // add carry from previous add to high word (edx)
      "addl %3,%[w0]\n\t"  // add c to low word (eax)
      "adcl %4,%[w1]\n\t"  // add carry from previous add to high word (edx)
      "adcl $0,%[w2]\n\t"  // add carry from previous add to high word (edx)
      : [w0]"=r"(*w0), [w1]"=r"(*w1), [w2]"=r"(*w2)
      : "a"(x), [y]"d"(y), "0"(*w0), "1"(*w1), "2"(*w2)
      : "cc");
   }

}

}

#endif
