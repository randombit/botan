/*************************************************
* Multiply/Add Algorithm Source File             *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(mp_muladd.S)

START_FUNCTION(bigint_mul_add_words)

#define Z_ARR    ARG_1
#define X_ARR    ARG_2
#define X_SIZE   %edx
#define Y        ARG_4

#define CARRY    TEMP_1
#define Z_WORD   TEMP_2
#define LOOP_CTR %r9d
#define MUL_LO   %rax
#define MUL_HI   %rdx

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

.L_MULADD_DONE:
   RETURN_VALUE_IS(CARRY)
END_FUNCTION(bigint_mul_add_words)
