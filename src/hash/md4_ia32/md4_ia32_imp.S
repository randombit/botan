/*
* MD4 Source File
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(md4_ia32.S)

START_FUNCTION(botan_md4_ia32_compress)
   SPILL_REGS()

#define PUSHED 4

   ASSIGN(EBP, ARG(2)) /* input block */
   ASSIGN(EDI, ARG(3)) /* expanded words */

   ZEROIZE(ESI)

START_LOOP(.LOAD_INPUT)
   ADD_IMM(ESI, 4)

   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

   ADD_IMM(EBP, 16)

   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-4), EAX)
   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-3), EBX)
   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-2), ECX)
   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-1), EDX)
LOOP_UNTIL_EQ(ESI, 16, .LOAD_INPUT)

   ASSIGN(EBP, ARG(1))
   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

#define MSG EDI
#define T1 ESI
#define T2 EBP

#define FF(A, B, C, D, N, S)          \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, C)                    ; \
   XOR(T2, D)                       ; \
   AND(T2, B)                       ; \
   XOR(T2, D)                       ; \
   ADD(A, T1)                       ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ;

#define GG(A, B, C, D, N, S)          \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, B)                    ; \
   OR(T2, C)                        ; \
   AND(T2, D)                       ; \
   ADD3_IMM(A, T1, 0x5A827999)      ; \
   ASSIGN(T1, B)                    ; \
   AND(T1, C)                       ; \
   OR(T2, T1)                       ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ;

#define HH(A, B, C, D, N, S)          \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, B)                    ; \
   XOR(T2, C)                       ; \
   XOR(T2, D)                       ; \
   ADD3_IMM(A, T1, 0x6ED9EBA1)      ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ;

   FF(EAX,EBX,ECX,EDX, 0, 3);
   FF(EDX,EAX,EBX,ECX, 1, 7);
   FF(ECX,EDX,EAX,EBX, 2,11);
   FF(EBX,ECX,EDX,EAX, 3,19);
   FF(EAX,EBX,ECX,EDX, 4, 3);
   FF(EDX,EAX,EBX,ECX, 5, 7);
   FF(ECX,EDX,EAX,EBX, 6,11);
   FF(EBX,ECX,EDX,EAX, 7,19);
   FF(EAX,EBX,ECX,EDX, 8, 3);
   FF(EDX,EAX,EBX,ECX, 9, 7);
   FF(ECX,EDX,EAX,EBX,10,11);
   FF(EBX,ECX,EDX,EAX,11,19);
   FF(EAX,EBX,ECX,EDX,12, 3);
   FF(EDX,EAX,EBX,ECX,13, 7);
   FF(ECX,EDX,EAX,EBX,14,11);
   FF(EBX,ECX,EDX,EAX,15,19);

   GG(EAX,EBX,ECX,EDX, 0, 3);
   GG(EDX,EAX,EBX,ECX, 4, 5);
   GG(ECX,EDX,EAX,EBX, 8, 9);
   GG(EBX,ECX,EDX,EAX,12,13);
   GG(EAX,EBX,ECX,EDX, 1, 3);
   GG(EDX,EAX,EBX,ECX, 5, 5);
   GG(ECX,EDX,EAX,EBX, 9, 9);
   GG(EBX,ECX,EDX,EAX,13,13);
   GG(EAX,EBX,ECX,EDX, 2, 3);
   GG(EDX,EAX,EBX,ECX, 6, 5);
   GG(ECX,EDX,EAX,EBX,10, 9);
   GG(EBX,ECX,EDX,EAX,14,13);
   GG(EAX,EBX,ECX,EDX, 3, 3);
   GG(EDX,EAX,EBX,ECX, 7, 5);
   GG(ECX,EDX,EAX,EBX,11, 9);
   GG(EBX,ECX,EDX,EAX,15,13);

   HH(EAX,EBX,ECX,EDX, 0, 3);
   HH(EDX,EAX,EBX,ECX, 8, 9);
   HH(ECX,EDX,EAX,EBX, 4,11);
   HH(EBX,ECX,EDX,EAX,12,15);
   HH(EAX,EBX,ECX,EDX, 2, 3);
   HH(EDX,EAX,EBX,ECX,10, 9);
   HH(ECX,EDX,EAX,EBX, 6,11);
   HH(EBX,ECX,EDX,EAX,14,15);
   HH(EAX,EBX,ECX,EDX, 1, 3);
   HH(EDX,EAX,EBX,ECX, 9, 9);
   HH(ECX,EDX,EAX,EBX, 5,11);
   HH(EBX,ECX,EDX,EAX,13,15);
   HH(EAX,EBX,ECX,EDX, 3, 3);
   HH(EDX,EAX,EBX,ECX,11, 9);
   HH(ECX,EDX,EAX,EBX, 7,11);
   HH(EBX,ECX,EDX,EAX,15,15);

   ASSIGN(EBP, ARG(1))
   ADD(ARRAY4(EBP, 0), EAX)
   ADD(ARRAY4(EBP, 1), EBX)
   ADD(ARRAY4(EBP, 2), ECX)
   ADD(ARRAY4(EBP, 3), EDX)

   RESTORE_REGS()
END_FUNCTION(botan_md4_ia32_compress)
