/*************************************************
* Assembly Macros Header File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_ASM_MACROS_H__
#define BOTAN_EXT_ASM_MACROS_H__

/*************************************************
* General/Global Macros                          *
*************************************************/
#define ALIGN .p2align 4,,15

#define START_LISTING(FILENAME) \
   .file #FILENAME;             \
   .text;                       \
   .p2align 4,,15;

/*************************************************
* Function Definitions                           *
*************************************************/
#define START_FUNCTION(func_name) \
   .align   8;                    \
   ALIGN;                         \
   .global  func_name;            \
   .type    func_name,@function;  \
func_name:

#define END_FUNCTION(func_name) \
   ret

/*************************************************
* Loop Control                                   *
*************************************************/
#define START_LOOP(LABEL) \
   ALIGN; \
   LABEL##_LOOP:

#define LOOP_UNTIL(REG, NUM, LABEL) \
   cmpl NUM, REG; \
   jne LABEL##_LOOP

/*************************************************
* Register Names                                 *
*************************************************/
#define EAX %eax
#define EBX %ebx
#define ECX %ecx
#define EDX %edx
#define EBP %ebp
#define EDI %edi
#define ESI %esi
#define ESP %esp

/*************************************************
* Memory Access Operations                       *
*************************************************/
#define ARRAY1(REG, NUM) (NUM)(REG)
#define ARRAY4(REG, NUM) 4*(NUM)(REG)
#define ARRAY4_INDIRECT(BASE, OFFSET, NUM) 4*(NUM)(BASE,OFFSET,4)
#define ARG(NUM) 4*(PUSHED) + ARRAY4(ESP, NUM)

#define ASSIGN(TO, FROM) movl FROM, TO
#define ASSIGN_BYTE(TO, FROM) movzbl FROM, TO

#define PUSH(REG) pushl REG
#define POP(REG) popl REG

#define SPILL_REGS() \
   PUSH(EBP) ; \
   PUSH(EDI) ; \
   PUSH(ESI) ; \
   PUSH(EBX)

#define RESTORE_REGS() \
   POP(EBX) ;  \
   POP(ESI) ;  \
   POP(EDI) ;  \
   POP(EBP)

/*************************************************
* ALU Operations                                 *
*************************************************/
#define IMM(VAL) $VAL

#define ADD(TO, FROM) addl FROM, TO
#define ADD_IMM(TO, NUM) addl IMM(NUM), TO
#define SUB_IMM(TO, NUM) subl IMM(NUM), TO
#define ADD2_IMM(TO, FROM, NUM) leal NUM(FROM), TO
#define ADD3_IMM(TO, FROM, NUM) leal NUM(TO,FROM,1), TO

#define SHL_IMM(REG, SHIFT) shll IMM(SHIFT), REG
#define SHR_IMM(REG, SHIFT) shrl IMM(SHIFT), REG

#define XOR(TO, FROM) xorl FROM, TO
#define AND(TO, FROM) andl FROM, TO
#define OR(TO, FROM) orl FROM, TO
#define NOT(REG) notl REG
#define ZEROIZE(REG) XOR(REG, REG)

#define ROTL_IMM(REG, NUM) roll IMM(NUM), REG
#define ROTR_IMM(REG, NUM) rorl IMM(NUM), REG
#define BSWAP(REG) bswapl REG

#endif
