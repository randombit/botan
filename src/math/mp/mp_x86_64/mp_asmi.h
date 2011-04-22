/*
* Lowest Level MPI Algorithms
* (C) 1999-2010 Jack Lloyd
*     2006 Luca Piccarreta
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MP_ASM_INTERNAL_H__
#define BOTAN_MP_ASM_INTERNAL_H__

#include <botan/internal/mp_asm.h>

namespace Botan {

extern "C" {

/*
* Helper Macros for x86-64 Assembly
*/
#ifndef ASM
  #define ASM(x) x "\n\t"
#endif

#define ADDSUB2_OP(OPERATION, INDEX)                     \
        ASM("movq 8*" #INDEX "(%[y]), %[carry]")         \
        ASM(OPERATION " %[carry], 8*" #INDEX "(%[x])")   \

#define ADDSUB3_OP(OPERATION, INDEX)                     \
        ASM("movq 8*" #INDEX "(%[x]), %[carry]")         \
        ASM(OPERATION " 8*" #INDEX "(%[y]), %[carry]")   \
        ASM("movq %[carry], 8*" #INDEX "(%[z])")         \

#define LINMUL_OP(WRITE_TO, INDEX)                       \
        ASM("movq 8*" #INDEX "(%[x]),%%rax")             \
        ASM("mulq %[y]")                                 \
        ASM("addq %[carry],%%rax")                       \
        ASM("adcq $0,%%rdx")                             \
        ASM("movq %%rdx,%[carry]")                       \
        ASM("movq %%rax, 8*" #INDEX "(%[" WRITE_TO "])")

#define MULADD_OP(IGNORED, INDEX)                        \
        ASM("movq 8*" #INDEX "(%[x]),%%rax")             \
        ASM("mulq %[y]")                                 \
        ASM("addq %[carry],%%rax")                       \
        ASM("adcq $0,%%rdx")                             \
        ASM("addq 8*" #INDEX "(%[z]),%%rax")             \
        ASM("adcq $0,%%rdx")                             \
        ASM("movq %%rdx,%[carry]")                       \
        ASM("movq %%rax, 8*" #INDEX " (%[z])")

#define DO_8_TIMES(MACRO, ARG) \
        MACRO(ARG, 0) \
        MACRO(ARG, 1) \
        MACRO(ARG, 2) \
        MACRO(ARG, 3) \
        MACRO(ARG, 4) \
        MACRO(ARG, 5) \
        MACRO(ARG, 6) \
        MACRO(ARG, 7)

#define ADD_OR_SUBTRACT(CORE_CODE)     \
        ASM("rorq %[carry]")           \
        CORE_CODE                      \
        ASM("sbbq %[carry],%[carry]")  \
        ASM("negq %[carry]")

/*
* Word Addition
*/
inline word word_add(word x, word y, word* carry)
   {
   asm(
      ADD_OR_SUBTRACT(ASM("adcq %[y],%[x]"))
      : [x]"=r"(x), [carry]"=r"(*carry)
      : "0"(x), [y]"rm"(y), "1"(*carry)
      : "cc");
   return x;
   }

/*
* Eight Word Block Addition, Two Argument
*/
inline word word8_add2(word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB2_OP, "adcq"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*
* Eight Word Block Addition, Three Argument
*/
inline word word8_add3(word z[8], const word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB3_OP, "adcq"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), [z]"r"(z), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*
* Word Subtraction
*/
inline word word_sub(word x, word y, word* carry)
   {
   asm(
      ADD_OR_SUBTRACT(ASM("sbbq %[y],%[x]"))
      : [x]"=r"(x), [carry]"=r"(*carry)
      : "0"(x), [y]"rm"(y), "1"(*carry)
      : "cc");
   return x;
   }

/*
* Eight Word Block Subtraction, Two Argument
*/
inline word word8_sub2(word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB2_OP, "sbbq"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*
* Eight Word Block Subtraction, Two Argument
*/
inline word word8_sub2_rev(word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB3_OP, "sbbq"))
      : [carry]"=r"(carry)
      : [x]"r"(y), [y]"r"(x), [z]"r"(x), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*
* Eight Word Block Subtraction, Three Argument
*/
inline word word8_sub3(word z[8], const word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB3_OP, "sbbq"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), [z]"r"(z), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*
* Eight Word Block Linear Multiplication
*/
inline word word8_linmul2(word x[8], word y, word carry)
   {
   asm(
      DO_8_TIMES(LINMUL_OP, "x")
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"rm"(y), "0"(carry)
      : "cc", "%rax", "%rdx");
   return carry;
   }

/*
* Eight Word Block Linear Multiplication
*/
inline word word8_linmul3(word z[8], const word x[8], word y, word carry)
   {
   asm(
      DO_8_TIMES(LINMUL_OP, "z")
      : [carry]"=r"(carry)
      : [z]"r"(z), [x]"r"(x), [y]"rm"(y), "0"(carry)
      : "cc", "%rax", "%rdx");
   return carry;
   }

/*
* Eight Word Block Multiply/Add
*/
inline word word8_madd3(word z[8], const word x[8], word y, word carry)
   {
   asm(
      DO_8_TIMES(MULADD_OP, "")
      : [carry]"=r"(carry)
      : [z]"r"(z), [x]"r"(x), [y]"rm"(y), "0"(carry)
      : "cc", "%rax", "%rdx");
   return carry;
   }

/*
* Multiply-Add Accumulator
*/
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

/*
* Multiply-Add Accumulator
*/
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


#undef ASM
#undef DO_8_TIMES
#undef ADD_OR_SUBTRACT
#undef ADDSUB2_OP
#undef ADDSUB3_OP
#undef LINMUL_OP
#undef MULADD_OP

}

}
#endif
