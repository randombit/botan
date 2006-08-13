/*************************************************
* MD5 Source File                                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(md5core.S)

START_FUNCTION(md5_core)
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
LOOP_UNTIL(ESI, IMM(16), .LOAD_INPUT)
   
   ASSIGN(EBP, ARG(1))
   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

#define T EBP
   
#define FF(A, B, C, D, MSG, S, MAGIC)    \
   ASSIGN(T, C)                        ; \
   XOR(T, D)                           ; \
   AND(T, B)                           ; \
   XOR(T, D)                           ; \
   ADD(A, ARRAY4(EDI, MSG))            ; \
   ADD3_IMM(A, T, MAGIC)               ; \
   ROTL_IMM(A, S)                      ; \
   ADD(A, B)                           ;

#define GG(A, B, C, D, MSG, S, MAGIC)    \
   ASSIGN(T, B)                        ; \
   XOR(T, C)                           ; \
   AND(T, D)                           ; \
   XOR(T, C)                           ; \
   ADD(A, ARRAY4(EDI, MSG))            ; \
   ADD3_IMM(A, T, MAGIC)               ; \
   ROTL_IMM(A, S)                      ; \
   ADD(A, B)                           ;

#define HH(A, B, C, D, MSG, S, MAGIC)    \
   ASSIGN(T, B)                        ; \
   XOR(T, C)                           ; \
   XOR(T, D)                           ; \
   ADD(A, ARRAY4(EDI, MSG))            ; \
   ADD3_IMM(A, T, MAGIC)               ; \
   ROTL_IMM(A, S)                      ; \
   ADD(A, B)                           ;

#define II(A, B, C, D, MSG, S, MAGIC)    \
   ASSIGN(T, D)                        ; \
   NOT(T)                              ; \
   OR(T, B)                            ; \
   XOR(T, C)                           ; \
   ADD(A, ARRAY4(EDI, MSG))            ; \
   ADD3_IMM(A, T, MAGIC)               ; \
   ROTL_IMM(A, S)                      ; \
   ADD(A, B)                           ;

#define A EAX
#define B EBX
#define C ECX
#define D EDX
   
   FF(A,B,C,D, 0, 7,0xD76AA478);   FF(D,A,B,C, 1,12,0xE8C7B756);
   FF(C,D,A,B, 2,17,0x242070DB);   FF(B,C,D,A, 3,22,0xC1BDCEEE);
   FF(A,B,C,D, 4, 7,0xF57C0FAF);   FF(D,A,B,C, 5,12,0x4787C62A);
   FF(C,D,A,B, 6,17,0xA8304613);   FF(B,C,D,A, 7,22,0xFD469501);
   FF(A,B,C,D, 8, 7,0x698098D8);   FF(D,A,B,C, 9,12,0x8B44F7AF);
   FF(C,D,A,B,10,17,0xFFFF5BB1);   FF(B,C,D,A,11,22,0x895CD7BE);
   FF(A,B,C,D,12, 7,0x6B901122);   FF(D,A,B,C,13,12,0xFD987193);
   FF(C,D,A,B,14,17,0xA679438E);   FF(B,C,D,A,15,22,0x49B40821);

   GG(A,B,C,D, 1, 5,0xF61E2562);   GG(D,A,B,C, 6, 9,0xC040B340);
   GG(C,D,A,B,11,14,0x265E5A51);   GG(B,C,D,A, 0,20,0xE9B6C7AA);
   GG(A,B,C,D, 5, 5,0xD62F105D);   GG(D,A,B,C,10, 9,0x02441453);
   GG(C,D,A,B,15,14,0xD8A1E681);   GG(B,C,D,A, 4,20,0xE7D3FBC8);
   GG(A,B,C,D, 9, 5,0x21E1CDE6);   GG(D,A,B,C,14, 9,0xC33707D6);
   GG(C,D,A,B, 3,14,0xF4D50D87);   GG(B,C,D,A, 8,20,0x455A14ED);
   GG(A,B,C,D,13, 5,0xA9E3E905);   GG(D,A,B,C, 2, 9,0xFCEFA3F8);
   GG(C,D,A,B, 7,14,0x676F02D9);   GG(B,C,D,A,12,20,0x8D2A4C8A);

   HH(A,B,C,D, 5, 4,0xFFFA3942);   HH(D,A,B,C, 8,11,0x8771F681);
   HH(C,D,A,B,11,16,0x6D9D6122);   HH(B,C,D,A,14,23,0xFDE5380C);
   HH(A,B,C,D, 1, 4,0xA4BEEA44);   HH(D,A,B,C, 4,11,0x4BDECFA9);
   HH(C,D,A,B, 7,16,0xF6BB4B60);   HH(B,C,D,A,10,23,0xBEBFBC70);
   HH(A,B,C,D,13, 4,0x289B7EC6);   HH(D,A,B,C, 0,11,0xEAA127FA);
   HH(C,D,A,B, 3,16,0xD4EF3085);   HH(B,C,D,A, 6,23,0x04881D05);
   HH(A,B,C,D, 9, 4,0xD9D4D039);   HH(D,A,B,C,12,11,0xE6DB99E5);
   HH(C,D,A,B,15,16,0x1FA27CF8);   HH(B,C,D,A, 2,23,0xC4AC5665);

   II(A,B,C,D, 0, 6,0xF4292244);   II(D,A,B,C, 7,10,0x432AFF97);
   II(C,D,A,B,14,15,0xAB9423A7);   II(B,C,D,A, 5,21,0xFC93A039);
   II(A,B,C,D,12, 6,0x655B59C3);   II(D,A,B,C, 3,10,0x8F0CCC92);
   II(C,D,A,B,10,15,0xFFEFF47D);   II(B,C,D,A, 1,21,0x85845DD1);
   II(A,B,C,D, 8, 6,0x6FA87E4F);   II(D,A,B,C,15,10,0xFE2CE6E0);
   II(C,D,A,B, 6,15,0xA3014314);   II(B,C,D,A,13,21,0x4E0811A1);
   II(A,B,C,D, 4, 6,0xF7537E82);   II(D,A,B,C,11,10,0xBD3AF235);
   II(C,D,A,B, 2,15,0x2AD7D2BB);   II(B,C,D,A, 9,21,0xEB86D391);

   ASSIGN(EBP, ARG(1))
   ADD(ARRAY4(EBP, 0), EAX)
   ADD(ARRAY4(EBP, 1), EBX)
   ADD(ARRAY4(EBP, 2), ECX)
   ADD(ARRAY4(EBP, 3), EDX)

   RESTORE_REGS()
END_FUNCTION(sha160_core)
