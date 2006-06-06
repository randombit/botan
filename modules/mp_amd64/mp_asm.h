/*************************************************
* Lowest Level MPI Algorithms Header File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_ASM_H__
#define BOTAN_MP_ASM_H__

#include <botan/mp_types.h>

#if (BOTAN_MP_WORD_BITS != 64)
   #error The mp_amd64 module requires that BOTAN_MP_WORD_BITS == 64
#endif

namespace Botan {

extern "C" {

/*************************************************
* Helper Macros for amd64 Assembly               *
*************************************************/
#define ASM(x) x "\n\t"

/*************************************************
* Word Multiply                                  *
*************************************************/
inline word word_madd2(word a, word b, word c, word* carry)
   {
   asm(
      ASM("mulq %[b]")
      ASM("addq %[c],%[a]")
      ASM("adcq $0,%[carry]")

      : [a]"=a"(a), [b]"=rm"(b), [carry]"=&d"(*carry)
      : "0"(a), "1"(b), [c]"g"(c) : "cc");

   return a;
   }

/*************************************************
* Word Multiply/Add                              *
*************************************************/
inline word word_madd3(word a, word b, word c, word d, word* carry)
   {
   asm(
      ASM("mulq %[b]")

      ASM("addq %[c],%[a]")
      ASM("adcq $0,%[carry]")

      ASM("addq %[d],%[a]")
      ASM("adcq $0,%[carry]")

      : [a]"=a"(a), [b]"=rm"(b), [carry]"=&d"(*carry)
      : "0"(a), "1"(b), [c]"g"(c), [d]"g"(d) : "cc");

   return a;
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd(word* w2, word* w1, word* w0, word x, word y)
   {
   asm(
      ASM("mulq %[y]")

      ASM("addq %[x],%[w0]")
      ASM("adcq %[y],%[w1]")
      ASM("adcq $0,%[w2]")

      : [w0]"=r"(*w0), [w1]"=r"(*w1), [w2]"=r"(*w2)
      : [x]"a"(x), [y]"d"(y), "0"(*w0), "1"(*w1), "2"(*w2)
      : "cc");
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd_2(word* w2, word* w1, word* w0, word x, word y)
   {
   asm(
      ASM("mulq %[y]")

      ASM("addq %[x],%[w0]")
      ASM("adcq %[y],%[w1]")
      ASM("adcq $0,%[w2]")

      ASM("addq %[x],%[w0]")
      ASM("adcq %[y],%[w1]")
      ASM("adcq $0,%[w2]")

      : [w0]"=r"(*w0), [w1]"=r"(*w1), [w2]"=r"(*w2)
      : [x]"a"(x), [y]"d"(y), "0"(*w0), "1"(*w1), "2"(*w2)
      : "cc");
   }

}

}

#endif
