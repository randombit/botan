/*************************************************
* Lowest Level MPI Algorithms Header File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_ASM_INTERNAL_H__
#define BOTAN_MP_ASM_INTERNAL_H__

#include <botan/mp_types.h>

namespace Botan {

/*************************************************
* Helper Macros for x86 Assembly                 *
*************************************************/
#define ASM(x) x "\n\t"

#define ADDSUB2_OP(OPERATION, INDEX)                    \
        ASM("movl 4*" INDEX "(%[y]), %[carry]")         \
        ASM(OPERATION " %[carry], 4*" INDEX "(%[x])")   \

#define ADDSUB3_OP(OPERATION, INDEX)                    \
        ASM("movl 4*" INDEX "(%[x]), %[carry]")         \
        ASM(OPERATION " 4*" INDEX "(%[y]), %[carry]")   \
        ASM("movl %[carry], 4*" INDEX "(%[z])")         \

#define LINMUL_OP(WRITE_TO, INDEX)                      \
        ASM("movl 4*" INDEX "(%[x]),%%eax")             \
        ASM("mull %[y]")                                \
        ASM("addl %[carry],%%eax")                      \
        ASM("adcl $0,%%edx")                            \
        ASM("movl %%edx,%[carry]")                      \
        ASM("movl %%eax, 4*" INDEX "(%[" WRITE_TO "])")

#define MULADD_OP(IGNORED, INDEX)                       \
        ASM("movl 4*" INDEX "(%[x]),%%eax")             \
        ASM("mull %[y]")                                \
        ASM("addl %[carry],%%eax")                      \
        ASM("adcl $0,%%edx")                            \
        ASM("addl 4*" INDEX "(%[z]),%%eax")             \
        ASM("adcl $0,%%edx")                            \
        ASM("movl %%edx,%[carry]")                      \
        ASM("movl %%eax, 4*" INDEX " (%[z])")

#define DO_8_TIMES(MACRO, ARG) \
        MACRO(ARG, "0") \
        MACRO(ARG, "1") \
        MACRO(ARG, "2") \
        MACRO(ARG, "3") \
        MACRO(ARG, "4") \
        MACRO(ARG, "5") \
        MACRO(ARG, "6") \
        MACRO(ARG, "7")

#define ADD_OR_SUBTRACT(CORE_CODE)     \
        ASM("rorl %[carry]")           \
        CORE_CODE                      \
        ASM("sbbl %[carry],%[carry]")  \
        ASM("negl %[carry]")

/*************************************************
* Word Addition                                  *
*************************************************/
inline word word_add(word x, word y, word* carry)
   {
   asm(
      ADD_OR_SUBTRACT(ASM("adcl %[y],%[x]"))
      : [x]"=r"(x), [carry]"=r"(*carry)
      : "0"(x), [y]"rm"(y), "1"(*carry)
      : "cc");
   return x;
   }

/*************************************************
* Eight Word Block Addition, Two Argument        *
*************************************************/
inline word word8_add2(word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB2_OP, "adcl"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*************************************************
* Eight Word Block Addition, Three Argument      *
*************************************************/
inline word word8_add3(word z[8], const word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB3_OP, "adcl"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), [z]"r"(z), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*************************************************
* Word Subtraction                               *
*************************************************/
inline word word_sub(word x, word y, word* carry)
   {
   asm(
      ADD_OR_SUBTRACT(ASM("sbbl %[y],%[x]"))
      : [x]"=r"(x), [carry]"=r"(*carry)
      : "0"(x), [y]"rm"(y), "1"(*carry)
      : "cc");
   return x;
   }

/*************************************************
* Eight Word Block Subtraction, Two Argument     *
*************************************************/
inline word word8_sub2(word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB2_OP, "sbbl"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*************************************************
* Eight Word Block Subtraction, Three Argument   *
*************************************************/
inline word word8_sub3(word z[8], const word x[8], const word y[8], word carry)
   {
   asm(
      ADD_OR_SUBTRACT(DO_8_TIMES(ADDSUB3_OP, "sbbl"))
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"r"(y), [z]"r"(z), "0"(carry)
      : "cc", "memory");
   return carry;
   }

/*************************************************
* Eight Word Block Linear Multiplication         *
*************************************************/
inline word word8_linmul2(word x[8], word y, word carry)
   {
   asm(
      DO_8_TIMES(LINMUL_OP, "x")
      : [carry]"=r"(carry)
      : [x]"r"(x), [y]"rm"(y), "0"(carry)
      : "cc", "%eax", "%edx");
   return carry;
   }

/*************************************************
* Eight Word Block Linear Multiplication          *
*************************************************/
inline word word8_linmul3(word z[8], const word x[8], word y, word carry)
   {
   asm(
      DO_8_TIMES(LINMUL_OP, "z")
      : [carry]"=r"(carry)
      : [z]"r"(z), [x]"r"(x), [y]"rm"(y), "0"(carry)
      : "cc", "%eax", "%edx");
   return carry;
   }

/*************************************************
* Eight Word Block Multiply/Add                  *
*************************************************/
inline word word8_madd3(word z[8], const word x[8], word y, word carry)
   {
   asm(
      DO_8_TIMES(MULADD_OP, "")
      : [carry]"=r"(carry)
      : [z]"r"(z), [x]"r"(x), [y]"rm"(y), "0"(carry)
      : "cc", "%eax", "%edx");
   return carry;
   }

}

#endif
