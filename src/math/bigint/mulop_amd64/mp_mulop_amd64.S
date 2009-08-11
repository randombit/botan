/*
* Simple O(N^2) Multiplication and Squaring
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(mp_mulop.S)

#if 0
void bigint_simple_sqr(word z[], const word x[], u32bit x_size)
   {
   const u32bit blocks = x_size - (x_size % 8);

   clear_mem(z, 2*x_size);

   for(u32bit i = 0; i != x_size; ++i)
      {
      word carry = 0;

      /*
      for(u32bit j = 0; j != blocks; j += 8)
         carry = word8_madd3(z + i + j, x + j, x[i], carry);

      for(u32bit j = blocks; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], x[i], z[i+j], &carry);
      */


      for(u32bit j = 0; j != x_size; ++j)
         z[i+j] = word_madd3(x[j], x[i], z[i+j], &carry);

      for(u32bit j = 0; j != x_size; ++j)
         {
         dword z = (dword)a * b + c + *d;
         *d = (word)(z >> BOTAN_MP_WORD_BITS);
         return (word)z;
         }

   
   
         z[i+j] = word_madd3(x[j], x[i], z[i+j], &carry);

   }

   

      z[x_size+i] = carry;
      }
   }

#endif

START_FUNCTION(bigint_simple_sqr)

#define Z_ARR    ARG_1
#define X_ARR    ARG_2
//#define X_SIZE   ARG_3_32

#define CARRY    TEMP_1
#define Z_WORD   TEMP_2
#define LOOP_I   TEMP_3
#define LOOP_J   TEMP_4
#define X_SIZE   TEMP_5
#define MUL_LO   %rax
// arg 3, xsize
#define MUL_HI   %rdx
   
// need arg3 == rdx for multiply
   ASSIGN(X_SIZE, ARG3_32)

   ZEROIZE(CARRY)

   ZEROIZE(LOOP_I)

.LOOP_ZEROIZE_Z:

   cmp LOOP_I, X_SIZE



   
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
END_FUNCTION(bigint_simple_square)
