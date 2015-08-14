/*
* Lowest Level MPI Algorithms
* (C) 1999-2008 Jack Lloyd
*     2006 Luca Piccarreta
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MP_WORD_MULADD_H__
#define BOTAN_MP_WORD_MULADD_H__

#include <botan/mp_types.h>

#if (BOTAN_MP_WORD_BITS != 64)
   #error The mp_x86_64 module requires that BOTAN_MP_WORD_BITS == 64
#endif

namespace Botan {

/*
* Helper Macros for x86-64 Assembly
*/
#define ASM(x) x "\n\t"

/*
* Word Multiply
*/
inline word word_madd2(word a, word b, word* c)
   {
   asm(
      ASM("mulq %[b]")
      ASM("addq %[c],%[a]")
      ASM("adcq $0,%[carry]")

      : [a]"=a"(a), [b]"=rm"(b), [carry]"=&d"(*c)
      : "0"(a), "1"(b), [c]"g"(*c) : "cc");

   return a;
   }

/*
* Word Multiply/Add
*/
inline word word_madd3(word a, word b, word c, word* d)
   {
   asm(
      ASM("mulq %[b]")

      ASM("addq %[c],%[a]")
      ASM("adcq $0,%[carry]")

      ASM("addq %[d],%[a]")
      ASM("adcq $0,%[carry]")

      : [a]"=a"(a), [b]"=rm"(b), [carry]"=&d"(*d)
      : "0"(a), "1"(b), [c]"g"(c), [d]"g"(*d) : "cc");

   return a;
   }

#undef ASM

}

#endif
