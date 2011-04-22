/*
* Assembly Macros for 64-bit x86
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ASM_MACROS_X86_64_H__
#define BOTAN_ASM_MACROS_X86_64_H__

/*
* General/Global Macros
*/
#define ALIGN .p2align 4,,15

#define START_LISTING(FILENAME) \
   .file #FILENAME;             \
   .text;                       \
   ALIGN;

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

/*
* Function Definitions
*/
#define START_FUNCTION(func_name) \
   ALIGN;                         \
   .global  func_name;            \
   .type    func_name,@function;  \
func_name:

#define END_FUNCTION(func_name) \
   ret

/*
* Conditional Jumps
*/
#define JUMP_IF_ZERO(REG, LABEL) \
   cmp IMM(0), REG;              \
   jz LABEL

#define JUMP_IF_LT(REG, NUM, LABEL) \
   cmp IMM(NUM), REG;               \
   jl LABEL

/*
* Register Names
*/
#define R0  %rax
#define R1  %rbx
#define R2  %rcx
#define R2_32  %ecx
#define R3  %rdx
#define R3_32  %edx
#define R4  %rsp
#define R5  %rbp
#define R6  %rsi
#define R6_32  %esi
#define R7  %rdi
#define R8  %r8
#define R9  %r9
#define R9_32  %r9d
#define R10 %r10
#define R11 %r11
#define R12 %r12
#define R13 %r13
#define R14 %r14
#define R15 %r15
#define R16 %r16

#define ARG_1 R7
#define ARG_2 R6
#define ARG_2_32 R6_32
#define ARG_3 R3
#define ARG_3_32 R3_32
#define ARG_4 R2
#define ARG_4_32 R2_32
#define ARG_5 R8
#define ARG_6 R9
#define ARG_6_32 R9_32

#define TEMP_1 R10
#define TEMP_2 R11
#define TEMP_3 ARG_6
#define TEMP_4 ARG_5
#define TEMP_5 ARG_4
#define TEMP_5_32 ARG_4_32
#define TEMP_6 ARG_3
#define TEMP_7 ARG_2
#define TEMP_8 ARG_1
#define TEMP_9 R0

/*
* Memory Access Operations
*/
#define ARRAY8(REG, NUM) 8*(NUM)(REG)
#define ARRAY4(REG, NUM) 4*(NUM)(REG)

#define ASSIGN(TO, FROM) mov FROM, TO

/*
* ALU Operations
*/
#define IMM(VAL) $VAL

#define ADD(TO, FROM) add FROM, TO
#define ADD_LAST_CARRY(REG) adc IMM(0), REG
#define ADD_IMM(TO, NUM) ADD(TO, IMM(NUM))
#define ADD_W_CARRY(TO1, TO2, FROM) add FROM, TO1; adc IMM(0), TO2;
#define SUB_IMM(TO, NUM) sub IMM(NUM), TO
#define MUL(REG) mul REG

#define XOR(TO, FROM) xor FROM, TO
#define AND(TO, FROM) and FROM, TO
#define OR(TO, FROM) or FROM, TO
#define NOT(REG) not REG
#define ZEROIZE(REG) XOR(REG, REG)

#define RETURN_VALUE_IS(V) ASSIGN(%rax, V)

#define ROTL_IMM(REG, NUM) rol IMM(NUM), REG
#define ROTR_IMM(REG, NUM) ror IMM(NUM), REG
#define ADD3_IMM(TO, FROM, NUM) lea NUM(TO,FROM,1), TO

#endif
