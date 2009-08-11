/*
* Multiply/Add Algorithm Source File
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(mp_muladd.S)

START_FUNCTION(bigint_mul_add_words)
   SPILL_REGS()
#define PUSHED 4

#define LOOP_CTR ESI
   ASSIGN(LOOP_CTR, ARG(3)) /* x_size */
   ZEROIZE(EDI)

   ASSIGN(ECX, ARG(1)) /* z[] */
   ASSIGN(EBX, ARG(2)) /* x[] */
   ASSIGN(EBP, ARG(4)) /* y */

#define MULADD_OP(N)                       \
   ASSIGN(EAX, ARRAY4(EBX, N))           ; \
   MUL(EBP)                              ; \
   ADD_W_CARRY(EAX, EDX, EDI)            ; \
   ASSIGN(EDI, EDX)                      ; \
   ADD_W_CARRY(ARRAY4(ECX, N), EDI, EAX) ;

   JUMP_IF_ZERO(LOOP_CTR, .MUL_ADD_DONE)
   JUMP_IF_LT(LOOP_CTR, 8, .MULADD1_LOOP)

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
   ADD_IMM(EBX, 32)
   ADD_IMM(ECX, 32)
LOOP_UNTIL_LT(LOOP_CTR, 8, .MULADD8)

   JUMP_IF_ZERO(LOOP_CTR, .MUL_ADD_DONE)

START_LOOP(.MULADD1)
   MULADD_OP(0)

   SUB_IMM(LOOP_CTR, 1)
   ADD_IMM(EBX, 4)
   ADD_IMM(ECX, 4)
LOOP_UNTIL_EQ(LOOP_CTR, 0, .MULADD1)

.MUL_ADD_DONE:

   ASSIGN(EAX, EDI)
#undef PUSHED
   RESTORE_REGS()
END_FUNCTION(bigint_mul_add_words)
