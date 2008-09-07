/*************************************************
* Montgomery Reduction Source File               *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(mp_monty.S)

START_FUNCTION(bigint_monty_redc)

#define Z_ARR    ARG_1 // rdi
#define Z_SIZE   ARG_2_32 // esi
#define X_ARR    ARG_3 // rdx
#define X_SIZE   ARG_4_32 // ecx
#define U        ARG_5 // r8

/*
     We need all arguments for a while (we can reuse U eventually)
   So only temp registers are
     TEMP_1 %r10
     TEMP_2 %r11
     TEMP_3 = ARG_6 = %r9
   void return, so also
     R0 %rax (aka TEMP_9)
   is free

   Can push:
     %rbx (base pointer, callee saved)
     %rpb (frame pointer, callee saved)
     %r12-%r15 (callee saved)

  Can push base/frame pointers since this is a leaf function
  and does not reference any data.
*/

   push %r12
   push %r13
   push %r14
   push %r15

#define LOOP_CTR R0

#define CARRY    TEMP_1
#define Z_WORD   TEMP_2
#define MUL_LO   %rax
#define MUL_HI   %rdx

   /*
   ZEROIZE(CARRY)

   ASSIGN(LOOP_CTR, X_SIZE)

   JUMP_IF_ZERO(LOOP_CTR, .L_MULADD_DONE)
   JUMP_IF_LT(LOOP_CTR, 8, .LOOP_MULADD1)

#define MULADD_OP(N)                  \
   ASSIGN(MUL_LO, ARRAY8(X_ARR, N)) ; \
   ASSIGN(Z_WORD, ARRAY8(Z_ARR, N)) ; \
   MUL(Y)                           ; \
   ADD(Z_WORD, CARRY)               ; \
   ASSIGN(CARRY, MUL_HI)            ; \
   ADD_LAST_CARRY(CARRY)            ; \
   ADD(Z_WORD, MUL_LO)              ; \
   ADD_LAST_CARRY(CARRY)            ; \
   ASSIGN(ARRAY8(Z_ARR, N), Z_WORD)

ALIGN
.LOOP_MULADD8:
   MULADD_OP(0)
   MULADD_OP(1)
   MULADD_OP(2)
   MULADD_OP(3)
   MULADD_OP(4)
   MULADD_OP(5)
   MULADD_OP(6)
   MULADD_OP(7)

   SUB_IMM(LOOP_CTR, 8)
   ADD_IMM(Z_ARR, 64)
   ADD_IMM(X_ARR, 64)
   cmp IMM(8), LOOP_CTR
   jge .LOOP_MULADD8

   JUMP_IF_ZERO(LOOP_CTR, .L_MULADD_DONE)

ALIGN
.LOOP_MULADD1:
   MULADD_OP(0)

   SUB_IMM(LOOP_CTR, 1)
   ADD_IMM(Z_ARR, 8)
   ADD_IMM(X_ARR, 8)

   cmp IMM(0), LOOP_CTR
   jne .LOOP_MULADD1
*/

   pop %r15
   pop %r14
   pop %r13
   pop %r12
END_FUNCTION(bigint_monty_redc)
