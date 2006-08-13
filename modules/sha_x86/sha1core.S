/*************************************************
* SHA-160 Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(sha1core.S)

FUNCTION(sha160_core)
   PUSH(EBP)
   PUSH(EDI)
   PUSH(ESI)
   PUSH(EBX)

#define PUSHED 4

   MOV(ARG(2), EBP)
   MOV(ARG(3), EDI)

   ZEROIZE(ESI)

START_LOOP(.LOAD_INPUT)
   ADD(IMM(4), ESI)

   MOV(ARRAY(EBP, 0), EAX)
   MOV(ARRAY(EBP, 1), EBX)
   MOV(ARRAY(EBP, 2), ECX)
   MOV(ARRAY(EBP, 3), EDX)

   ADD(IMM(16), EBP)

   BSWAP(EAX)
   BSWAP(EBX)
   BSWAP(ECX)
   BSWAP(EDX)

        movl   EAX, -16(EDI,ESI,4)
        movl   EBX, -12(EDI,ESI,4)
        movl   ECX, -8(EDI,ESI,4)
        movl   EDX, -4(EDI,ESI,4)
LOOP_UNTIL(ESI, IMM(16), .LOAD_INPUT)

   ADD2(EDI, 64, EBP)

START_LOOP(.EXPANSION)
   ADD(IMM(4), ESI)

   ZEROIZE(EAX)

   MOV(ARRAY(EBP, -1), EBX)
   MOV(ARRAY(EBP, -2), ECX)
   MOV(ARRAY(EBP, -3), EDX)

   XOR(ARRAY(EBP, -5), EAX)
   XOR(ARRAY(EBP, -6), EBX)
   XOR(ARRAY(EBP, -7), ECX)
   XOR(ARRAY(EBP, -8), EDX)

   XOR(ARRAY(EBP, -11), EAX)
   XOR(ARRAY(EBP, -12), EBX)
   XOR(ARRAY(EBP, -13), ECX)
   XOR(ARRAY(EBP, -14), EDX)

   XOR(ARRAY(EBP, -13), EAX)
   XOR(ARRAY(EBP, -14), EBX)
   XOR(ARRAY(EBP, -15), ECX)
   XOR(ARRAY(EBP, -16), EDX)

   ROTL(IMM(1), EDX)
   ROTL(IMM(1), ECX)
   ROTL(IMM(1), EBX)
   XOR(EDX, EAX)
   ROTL(IMM(1), EAX)

   MOV(EDX, ARRAY(EBP, 0))
   MOV(ECX, ARRAY(EBP, 1))
   MOV(EBX, ARRAY(EBP, 2))
   MOV(EAX, ARRAY(EBP, 3))

   ADD(IMM(16), EBP)
LOOP_UNTIL(ESI, IMM(80), .EXPANSION)

   MOV(ARG(1), EBP)
   MOV(ARRAY(EBP, 0), EAX)
   MOV(ARRAY(EBP, 1), EBX)
   MOV(ARRAY(EBP, 2), ECX)
   MOV(ARRAY(EBP, 3), EDX)
   MOV(ARRAY(EBP, 4), ESI)

#define MAGIC1 0x5A827999
#define MAGIC2 0x6ED9EBA1
#define MAGIC3 0x8F1BBCDC
#define MAGIC4 0xCA62C1D6

#define F1(A, B, C, D, E, TEMP, MSG) \
   ADD(ARRAY(EDI, MSG), E)      ; \
   MOV(C, TEMP)                 ; \
   ROTL(IMM(5), A)              ; \
   XOR(D, TEMP)                 ; \
   ADD(A, E)                    ; \
   AND(B, TEMP)                 ; \
   ROTR(IMM(2), B)              ; \
   XOR(D, TEMP)                 ; \
   leal MAGIC1(E,TEMP,1), E     ; \
   ROTR(IMM(5), A)              ; 
   
#define F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC) \
   ADD(ARRAY(EDI, MSG), E)      ; \
   MOV(B, TEMP)                 ; \
   ROTL(IMM(5), A)              ; \
   XOR(D, TEMP)                 ; \
   ADD(A, E)                    ; \
   XOR(C, TEMP)                 ; \
   ROTR(IMM(2), B)              ; \
   leal MAGIC(E,TEMP,1), E      ; \
   ROTR(IMM(5), A)              ; 

#define F3(A, B, C, D, E, TEMP, MSG) \
   ADD(ARRAY(EDI, MSG), E)      ; \
   MOV(B, TEMP)                 ; \
   ROTL(IMM(5), A)              ; \
   OR(C, TEMP)                  ; \
   MOV(B, ARRAY(EDI, MSG))      ; \
   AND(D, TEMP)                 ; \
   AND(C, ARRAY(EDI, MSG))      ; \
   OR(ARRAY(EDI, MSG), TEMP)    ; \
   ADD(A, E)                    ; \
   leal MAGIC3(E,TEMP,1), E     ; \
   ROTR(IMM(2), B)              ; \
   ROTR(IMM(5), A)              ; 

#define F2(A, B, C, D, E, TEMP, MSG) \
   F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC2)

#define F4(A, B, C, D, E, TEMP, MSG) \
   F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC4)

#define F_BLOCK(F, MSG) \
    F(EAX, EBX, ECX, EDX, ESI, EBP, (MSG+0)) \
    F(ESI, EAX, EBX, ECX, EDX, EBP, (MSG+1)) \
    F(EDX, ESI, EAX, EBX, ECX, EBP, (MSG+2)) \
    F(ECX, EDX, ESI, EAX, EBX, EBP, (MSG+3)) \
    F(EBX, ECX, EDX, ESI, EAX, EBP, (MSG+4))

   F_BLOCK(F1, 0)
   F_BLOCK(F1, 5)
   F_BLOCK(F1, 10)
   F_BLOCK(F1, 15)

   F_BLOCK(F2, 20)
   F_BLOCK(F2, 25)
   F_BLOCK(F2, 30)
   F_BLOCK(F2, 35)

   F_BLOCK(F3, 40)
   F_BLOCK(F3, 45)
   F_BLOCK(F3, 50)
   F_BLOCK(F3, 55)

   F_BLOCK(F4, 60)
   F_BLOCK(F4, 65)
   F_BLOCK(F4, 70)
   F_BLOCK(F4, 75)

   MOV(ARG(1), EBP)
   ADD(EAX, ARRAY(EBP, 0))
   ADD(EBX, ARRAY(EBP, 1))
   ADD(ECX, ARRAY(EBP, 2))
   ADD(EDX, ARRAY(EBP, 3))
   ADD(ESI, ARRAY(EBP, 4))

   POP(EBX)
   POP(ESI)
   POP(EDI)
   POP(EBP)
   ret
