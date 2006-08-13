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

#define PUSH(REG) pushl REG
#define POP(REG) popl REG
#define MOV(FROM, TO) movl FROM, TO


#define ADD(FROM, TO) addl FROM, TO
#define ADD2(FROM, NUM, TO) leal NUM(FROM), TO

#define XOR(FROM, TO) xorl FROM, TO
#define AND(FROM, TO) andl FROM, TO
#define OR(FROM, TO) orl FROM, TO
#define ROTL(NUM, REG) roll NUM, REG
#define ROTR(NUM, REG) rorl NUM, REG


#define ARRAY(REG, NUM) 4*NUM(REG)

#define BSWAP(REG) bswapl REG

#define IMM(VAL) $VAL

#define ZEROIZE(REG) xorl REG, REG

#define ARG(NUM) 4*PUSHED+4*NUM(%esp)

#endif
