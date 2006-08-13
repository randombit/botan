/*************************************************
* Assembly Macros Header File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_ASM_MACROS_H__
#define BOTAN_EXT_ASM_MACROS_H__

#define ALIGN .p2align 4,,15

#define START_LISTING(FILENAME) \
   .file #FILENAME;             \
   .text;                       \
   .p2align 4,,15;

#define FUNCTION(func_name)      \
   .align   8;                   \
   ALIGN;                        \
   .global  func_name;           \
   .type    func_name,@function; \
func_name:

#define LOOP_UNTIL(REG, NUM, LABEL) \
   cmpl NUM, REG; \
   jne LABEL##_LOOP

#define START_LOOP(LABEL) \
   ALIGN; \
   LABEL##_LOOP:

#define EAX %eax
#define EBX %ebx
#define ECX %ecx
#define EDX %edx
#define EBP %ebp
#define EDI %edi
#define ESI %esi
#define ESP %esp

#define IMM(VAL) $VAL

#define PUSH(REG) pushl REG
#define POP(REG) popl REG
#define ASSIGN(TO, FROM) movl FROM, TO
#define ARRAY(REG, NUM) 4*NUM(REG)
#define ARG(NUM) 4*PUSHED + ARRAY(ESP, NUM)

#define ADD(TO, FROM) addl FROM, TO
#define ADD_IMM(TO, NUM) addl IMM(NUM), TO
#define ADD2_IMM(TO, FROM, NUM) leal NUM(FROM), TO

#define XOR(TO, FROM) xorl FROM, TO
#define AND(TO, FROM) andl FROM, TO
#define OR(TO, FROM) orl FROM, TO
#define ZEROIZE(REG) XOR(REG, REG)

#define ROTL_IMM(REG, NUM) roll IMM(NUM), REG
#define ROTR_IMM(REG, NUM) rorl IMM(NUM), REG
#define BSWAP(REG) bswapl REG


#endif
