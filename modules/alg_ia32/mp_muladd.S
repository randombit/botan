
#include <botan/asm_macr.h>

START_LISTING(mp_muladd.S)

/*
word bigint_mul_add_words(word z[], const word x[], u32bit x_size, word y)
   {
   word carry = 0;

   for(u32bit j = 0; j != x_size; ++j)
      {
      u64bit zx = (u64bit)x[j] * y + z[j] + carry;
      z[j] = (word)zx;
      carry = (word)(zx >> BOTAN_MP_WORD_BITS);
      }

   return carry;
   }
*/
START_FUNCTION(bigint_mul_add_words)
   SPILL_REGS()
#define PUSHED 4

   ASSIGN(EBX, ARG(2)) /* x[] */
   ASSIGN(ECX, ARG(1)) /* z[] */
   ASSIGN(ESI, ARG(3)) /* x_size */
   ASSIGN(EBP, ARG(4)) /* y */
   ZEROIZE(EDI)

#define MULADD_OP(N)                       \
   ASSIGN(EAX, ARRAY4(EBX, N))           ; \
   MUL(EBP)                              ; \
   ADD_W_CARRY(EAX, EDX, EDI)            ; \
   ADD_W_CARRY(EAX, EDX, ARRAY4(ECX, N)) ; \
   ASSIGN(ARRAY4(ECX, N), EAX)           ; \
   ASSIGN(EDI, EDX)                      ;

   JUMP_IF_ZERO(ESI, .MUL_ADD_DONE)
   JUMP_IF_LT(ESI, 8, .MULADD1_LOOP)

START_LOOP(.MULADD8)
   MULADD_OP(0)
   MULADD_OP(1)
   MULADD_OP(2)
   MULADD_OP(3)
   MULADD_OP(4)
   MULADD_OP(5)
   MULADD_OP(6)
   MULADD_OP(7)

   SUB_IMM(ESI, 8)
   ADD_IMM(EBX, 32)
   ADD_IMM(ECX, 32)
LOOP_UNTIL_LT(ESI, 8, .MULADD8)

   JUMP_IF_ZERO(ESI, .MUL_ADD_DONE)

START_LOOP(.MULADD1)
   MULADD_OP(0)

   SUB_IMM(ESI, 1)
   ADD_IMM(EBX, 4)
   ADD_IMM(ECX, 4)
LOOP_UNTIL_EQ(ESI, 0, .MULADD1)

.MUL_ADD_DONE:

   ASSIGN(EAX, EDI)
#undef PUSHED
   RESTORE_REGS()
END_FUNCTION(bigint_mul_add_words)
