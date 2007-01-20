/*************************************************
* Assembly Macros Header File                    *
* (C) 1999-2007 The Botan Project                *
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
   ALIGN;

/*************************************************
* Function Definitions                           *
*************************************************/
#define START_FUNCTION(func_name) \
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
   ALIGN;                 \
   LABEL##_LOOP:

#define LOOP_UNTIL_EQ(REG, NUM, LABEL) \
   cmp IMM(NUM), REG;                  \
   jne LABEL##_LOOP

#define LOOP_UNTIL_LT(REG, NUM, LABEL) \
   cmp IMM(NUM), REG;                  \
   jge LABEL##_LOOP

/*************************************************
 Conditional Jumps                              *
*************************************************/
#define JUMP_IF_ZERO(REG, LABEL) \
   cmp IMM(0), REG;              \
   jz LABEL

#define JUMP_IF_LT(REG, NUM, LABEL) \
   cmp IMM(NUM), REG;               \
   jl LABEL

/*************************************************
* Memory Access Operations                       *
*************************************************/
#define ARRAY8(REG, NUM) 8*(NUM)(REG)

#define ASSIGN(TO, FROM) mov FROM, TO

/*************************************************
* ALU Operations                                 *
*************************************************/
#define IMM(VAL) $VAL

#define ADD(TO, FROM) addq FROM, TO
#define ADD_LAST_CARRY(REG) adcq IMM(0), REG
#define ADD_IMM(TO, NUM) ADD(TO, IMM(NUM))
#define ADD_W_CARRY(TO1, TO2, FROM) addq FROM, TO1; adcq IMM(0), TO2;
#define SUB_IMM(TO, NUM) sub IMM(NUM), TO
#define MUL(REG) mulq REG

#define XOR(TO, FROM) xorq FROM, TO
#define AND(TO, FROM) andq FROM, TO
#define OR(TO, FROM) orq FROM, TO
#define NOT(REG) notq REG
#define ZEROIZE(REG) XOR(REG, REG)

#define RETURN_VALUE_IS(V) ASSIGN(%rax, V)

#endif
