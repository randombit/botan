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

   ASSIGN(EBP, ARG(2))
   ASSIGN(EDI, ARG(3))

   ZEROIZE(ESI)

START_LOOP(.LOAD_INPUT)
   ADD_IMM(ESI, 4)

   ASSIGN(EAX, ARRAY(EBP, 0))
   ASSIGN(EBX, ARRAY(EBP, 1))
   ASSIGN(ECX, ARRAY(EBP, 2))
   ASSIGN(EDX, ARRAY(EBP, 3))

   ADD_IMM(EBP, 16)

   BSWAP(EAX)
   BSWAP(EBX)
   BSWAP(ECX)
   BSWAP(EDX)

   ASSIGN(-16(EDI,ESI,4), EAX)
   ASSIGN(-12(EDI,ESI,4), EBX)
   ASSIGN( -8(EDI,ESI,4), ECX)
   ASSIGN( -4(EDI,ESI,4), EDX)
LOOP_UNTIL(ESI, IMM(16), .LOAD_INPUT)

   ADD2_IMM(EBP, EDI, 64)

START_LOOP(.EXPANSION)
   ADD_IMM(ESI, 4)

   ZEROIZE(EAX)

   ASSIGN(EBX, ARRAY(EBP, -1))
   ASSIGN(ECX, ARRAY(EBP, -2))
   ASSIGN(EDX, ARRAY(EBP, -3))

   XOR(EAX, ARRAY(EBP, -5))
   XOR(EBX, ARRAY(EBP, -6))
   XOR(ECX, ARRAY(EBP, -7))
   XOR(EDX, ARRAY(EBP, -8))

   XOR(EAX, ARRAY(EBP, -11))
   XOR(EBX, ARRAY(EBP, -12))
   XOR(ECX, ARRAY(EBP, -13))
   XOR(EDX, ARRAY(EBP, -14))

   XOR(EAX, ARRAY(EBP, -13))
   XOR(EBX, ARRAY(EBP, -14))
   XOR(ECX, ARRAY(EBP, -15))
   XOR(EDX, ARRAY(EBP, -16))

   ROTL_IMM(EDX, 1)
   ROTL_IMM(ECX, 1)
   ROTL_IMM(EBX, 1)
   XOR(EAX, EDX)
   ROTL_IMM(EAX, 1)

   ASSIGN(ARRAY(EBP, 0), EDX)
   ASSIGN(ARRAY(EBP, 1), ECX)
   ASSIGN(ARRAY(EBP, 2), EBX)
   ASSIGN(ARRAY(EBP, 3), EAX)

   ADD_IMM(EBP, 16)
LOOP_UNTIL(ESI, IMM(80), .EXPANSION)

   ASSIGN(EBP, ARG(1))
   ASSIGN(EAX, ARRAY(EBP, 0))
   ASSIGN(EBX, ARRAY(EBP, 1))
   ASSIGN(ECX, ARRAY(EBP, 2))
   ASSIGN(EDX, ARRAY(EBP, 3))
   ASSIGN(ESI, ARRAY(EBP, 4))

#define MAGIC1 0x5A827999
#define MAGIC2 0x6ED9EBA1
#define MAGIC3 0x8F1BBCDC
#define MAGIC4 0xCA62C1D6

#define F1(A, B, C, D, E, TEMP, MSG) \
   ADD(E, ARRAY(EDI, MSG))      ; \
   ASSIGN(TEMP, C)              ; \
   ROTL_IMM(A, 5)               ; \
   XOR(TEMP, D)                 ; \
   ADD(E, A)                    ; \
   AND(B, TEMP)                 ; \
   ROTR_IMM(B, 2)               ; \
   XOR(TEMP, D)                 ; \
   leal MAGIC1(E,TEMP,1), E     ; \
   ROTR_IMM(A, 5)               ; 
   
#define F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC) \
   ADD(E, ARRAY(EDI, MSG))      ; \
   ASSIGN(TEMP, B)              ; \
   ROTL_IMM(A, 5)               ; \
   XOR(TEMP, D)                 ; \
   ADD(E, A)                    ; \
   XOR(TEMP, C)                 ; \
   ROTR_IMM(B, 2)               ; \
   leal MAGIC(E,TEMP,1), E      ; \
   ROTR_IMM(A, 5)               ; 

#define F3(A, B, C, D, E, TEMP, MSG) \
   ADD(E, ARRAY(EDI, MSG))      ; \
   ASSIGN(TEMP, B)              ; \
   ROTL_IMM(A, 5)               ; \
   OR(C, TEMP)                  ; \
   ASSIGN(ARRAY(EDI, MSG), B)   ; \
   AND(D, TEMP)                 ; \
   AND(C, ARRAY(EDI, MSG))      ; \
   OR(ARRAY(EDI, MSG), TEMP)    ; \
   ADD(E, A)                    ; \
   leal MAGIC3(E,TEMP,1), E     ; \
   ROTR_IMM(B, 2)               ; \
   ROTR_IMM(A, 5)               ; 

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

   ASSIGN(EBP, ARG(1))
   ADD(ARRAY(EBP, 0), EAX)
   ADD(ARRAY(EBP, 1), EBX)
   ADD(ARRAY(EBP, 2), ECX)
   ADD(ARRAY(EBP, 3), EDX)
   ADD(ARRAY(EBP, 4), ESI)

   POP(EBX)
   POP(ESI)
   POP(EDI)
   POP(EBP)
   ret
