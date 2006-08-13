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

#define EAX %eax
#define EBX %ebx
#define ECX %ecx
#define EDX %edx
#define EBP %ebp
#define EDI %edi
#define ESI %esi

#define PUSH(REG) pushl REG
#define MOV(FROM, TO) movl FROM, TO


#define ADD(FROM, TO) addl FROM, TO

#define IMM(VAL) $VAL

#define ZEROIZE(REG) xorl REG, REG

#define ARG(NUM) 4*PUSHED+4*NUM(%esp)

#endif
