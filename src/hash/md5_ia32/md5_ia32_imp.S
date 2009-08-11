/*
* MD5 Source File
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(md5_ia32.S)

START_FUNCTION(botan_md5_ia32_compress)
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

#define FF(A, B, C, D, N, S, MAGIC)   \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, C)                    ; \
   XOR(T2, D)                       ; \
   AND(T2, B)                       ; \
   XOR(T2, D)                       ; \
   ADD3_IMM(A, T1, MAGIC)           ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ; \
   ADD(A, B)                        ;

#define GG(A, B, C, D, N, S, MAGIC)   \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, B)                    ; \
   XOR(T2, C)                       ; \
   AND(T2, D)                       ; \
   XOR(T2, C)                       ; \
   ADD3_IMM(A, T1, MAGIC)           ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ; \
   ADD(A, B)                        ;

#define HH(A, B, C, D, N, S, MAGIC)   \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, B)                    ; \
   XOR(T2, C)                       ; \
   XOR(T2, D)                       ; \
   ADD3_IMM(A, T1, MAGIC)           ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ; \
   ADD(A, B)                        ;

#define II(A, B, C, D, N, S, MAGIC)   \
   ASSIGN(T1, ARRAY4(MSG, N))       ; \
   ASSIGN(T2, D)                    ; \
   NOT(T2)                          ; \
   OR(T2, B)                        ; \
   XOR(T2, C)                       ; \
   ADD3_IMM(A, T1, MAGIC)           ; \
   ADD(A, T2)                       ; \
   ROTL_IMM(A, S)                   ; \
   ADD(A, B)                        ;

   FF(EAX,EBX,ECX,EDX, 0, 7,0xD76AA478);
   FF(EDX,EAX,EBX,ECX, 1,12,0xE8C7B756);
   FF(ECX,EDX,EAX,EBX, 2,17,0x242070DB);
   FF(EBX,ECX,EDX,EAX, 3,22,0xC1BDCEEE);
   FF(EAX,EBX,ECX,EDX, 4, 7,0xF57C0FAF);
   FF(EDX,EAX,EBX,ECX, 5,12,0x4787C62A);
   FF(ECX,EDX,EAX,EBX, 6,17,0xA8304613);
   FF(EBX,ECX,EDX,EAX, 7,22,0xFD469501);
   FF(EAX,EBX,ECX,EDX, 8, 7,0x698098D8);
   FF(EDX,EAX,EBX,ECX, 9,12,0x8B44F7AF);
   FF(ECX,EDX,EAX,EBX,10,17,0xFFFF5BB1);
   FF(EBX,ECX,EDX,EAX,11,22,0x895CD7BE);
   FF(EAX,EBX,ECX,EDX,12, 7,0x6B901122);
   FF(EDX,EAX,EBX,ECX,13,12,0xFD987193);
   FF(ECX,EDX,EAX,EBX,14,17,0xA679438E);
   FF(EBX,ECX,EDX,EAX,15,22,0x49B40821);

   GG(EAX,EBX,ECX,EDX, 1, 5,0xF61E2562);
   GG(EDX,EAX,EBX,ECX, 6, 9,0xC040B340);
   GG(ECX,EDX,EAX,EBX,11,14,0x265E5A51);
   GG(EBX,ECX,EDX,EAX, 0,20,0xE9B6C7AA);
   GG(EAX,EBX,ECX,EDX, 5, 5,0xD62F105D);
   GG(EDX,EAX,EBX,ECX,10, 9,0x02441453);
   GG(ECX,EDX,EAX,EBX,15,14,0xD8A1E681);
   GG(EBX,ECX,EDX,EAX, 4,20,0xE7D3FBC8);
   GG(EAX,EBX,ECX,EDX, 9, 5,0x21E1CDE6);
   GG(EDX,EAX,EBX,ECX,14, 9,0xC33707D6);
   GG(ECX,EDX,EAX,EBX, 3,14,0xF4D50D87);
   GG(EBX,ECX,EDX,EAX, 8,20,0x455A14ED);
   GG(EAX,EBX,ECX,EDX,13, 5,0xA9E3E905);
   GG(EDX,EAX,EBX,ECX, 2, 9,0xFCEFA3F8);
   GG(ECX,EDX,EAX,EBX, 7,14,0x676F02D9);
   GG(EBX,ECX,EDX,EAX,12,20,0x8D2A4C8A);

   HH(EAX,EBX,ECX,EDX, 5, 4,0xFFFA3942);
   HH(EDX,EAX,EBX,ECX, 8,11,0x8771F681);
   HH(ECX,EDX,EAX,EBX,11,16,0x6D9D6122);
   HH(EBX,ECX,EDX,EAX,14,23,0xFDE5380C);
   HH(EAX,EBX,ECX,EDX, 1, 4,0xA4BEEA44);
   HH(EDX,EAX,EBX,ECX, 4,11,0x4BDECFA9);
   HH(ECX,EDX,EAX,EBX, 7,16,0xF6BB4B60);
   HH(EBX,ECX,EDX,EAX,10,23,0xBEBFBC70);
   HH(EAX,EBX,ECX,EDX,13, 4,0x289B7EC6);
   HH(EDX,EAX,EBX,ECX, 0,11,0xEAA127FA);
   HH(ECX,EDX,EAX,EBX, 3,16,0xD4EF3085);
   HH(EBX,ECX,EDX,EAX, 6,23,0x04881D05);
   HH(EAX,EBX,ECX,EDX, 9, 4,0xD9D4D039);
   HH(EDX,EAX,EBX,ECX,12,11,0xE6DB99E5);
   HH(ECX,EDX,EAX,EBX,15,16,0x1FA27CF8);
   HH(EBX,ECX,EDX,EAX, 2,23,0xC4AC5665);

   II(EAX,EBX,ECX,EDX, 0, 6,0xF4292244);
   II(EDX,EAX,EBX,ECX, 7,10,0x432AFF97);
   II(ECX,EDX,EAX,EBX,14,15,0xAB9423A7);
   II(EBX,ECX,EDX,EAX, 5,21,0xFC93A039);
   II(EAX,EBX,ECX,EDX,12, 6,0x655B59C3);
   II(EDX,EAX,EBX,ECX, 3,10,0x8F0CCC92);
   II(ECX,EDX,EAX,EBX,10,15,0xFFEFF47D);
   II(EBX,ECX,EDX,EAX, 1,21,0x85845DD1);
   II(EAX,EBX,ECX,EDX, 8, 6,0x6FA87E4F);
   II(EDX,EAX,EBX,ECX,15,10,0xFE2CE6E0);
   II(ECX,EDX,EAX,EBX, 6,15,0xA3014314);
   II(EBX,ECX,EDX,EAX,13,21,0x4E0811A1);
   II(EAX,EBX,ECX,EDX, 4, 6,0xF7537E82);
   II(EDX,EAX,EBX,ECX,11,10,0xBD3AF235);
   II(ECX,EDX,EAX,EBX, 2,15,0x2AD7D2BB);
   II(EBX,ECX,EDX,EAX, 9,21,0xEB86D391);

   ASSIGN(EBP, ARG(1))
   ADD(ARRAY4(EBP, 0), EAX)
   ADD(ARRAY4(EBP, 1), EBX)
   ADD(ARRAY4(EBP, 2), ECX)
   ADD(ARRAY4(EBP, 3), EDX)

   RESTORE_REGS()
END_FUNCTION(botan_md5_ia32_compress)
