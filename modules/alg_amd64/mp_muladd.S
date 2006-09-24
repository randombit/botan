/*************************************************
* Multiply/Add Algorithm Source File             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(mp_muladd.S)

START_FUNCTION(bigint_mul_add_words)
#define LOOP_CTR %r11d
#define X_ARR %rsi
#define Z_ARR %rdi
#define Y %rcx
#define CARRY %r8

   ZEROIZE(CARRY)

   ASSIGN(LOOP_CTR, %edx)

   JUMP_IF_ZERO(LOOP_CTR, .DONE)
   JUMP_IF_LT(LOOP_CTR, 8, .MULADD1_LOOP)

#define MULADD_OP(N)                \
   ASSIGN(%rax, ARRAY8(X_ARR, N)) ; \
   ASSIGN(%r9,  ARRAY8(Z_ARR, N)) ; \
   MUL(Y)                         ; \
   ADD_W_CARRY(%rax, %rdx, CARRY) ; \
   ADD_W_CARRY(%rax, %rdx, %r9)   ; \
   ASSIGN(CARRY, %rdx)            ; \
   ASSIGN(ARRAY8(Z_ARR, N), %rax)

START_LOOP(.MULADD8)
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
LOOP_UNTIL_LT(LOOP_CTR, 8, .MULADD8)

   JUMP_IF_ZERO(LOOP_CTR, .DONE)

START_LOOP(.MULADD1)
   MULADD_OP(0)

   SUB_IMM(LOOP_CTR, 1)
   ADD_IMM(Z_ARR, 8)
   ADD_IMM(X_ARR, 8)
LOOP_UNTIL_EQ(LOOP_CTR, 0, .MULADD1)

.DONE:
   ASSIGN(%rax, CARRY)
END_FUNCTION(bigint_mul_add_words)
