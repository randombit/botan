/*************************************************
* SHA-160 Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(sha1core.S)

START_FUNCTION(sha160_core)
   SPILL_REGS()

#define PUSHED 4

   ASSIGN(EBP, ARG(2))
   ASSIGN(EDI, ARG(3))

   ZEROIZE(ESI)

START_LOOP(.LOAD_INPUT)
   ADD_IMM(ESI, 4)

   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

   ADD_IMM(EBP, 16)

   BSWAP(EAX)
   BSWAP(EBX)
   BSWAP(ECX)
   BSWAP(EDX)

   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-4), EAX)
   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-3), EBX)
   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-2), ECX)
   ASSIGN(ARRAY4_INDIRECT(EDI,ESI,-1), EDX)
LOOP_UNTIL_EQ(ESI, 16, .LOAD_INPUT)

   ADD2_IMM(EBP, EDI, 64)

START_LOOP(.EXPANSION)
   ADD_IMM(ESI, 4)

   ZEROIZE(EAX)
   ASSIGN(EBX, ARRAY4(EBP, -1))
   ASSIGN(ECX, ARRAY4(EBP, -2))
   ASSIGN(EDX, ARRAY4(EBP, -3))

   XOR(EAX, ARRAY4(EBP, -5))
   XOR(EBX, ARRAY4(EBP, -6))
   XOR(ECX, ARRAY4(EBP, -7))
   XOR(EDX, ARRAY4(EBP, -8))

   XOR(EAX, ARRAY4(EBP, -11))
   XOR(EBX, ARRAY4(EBP, -12))
   XOR(ECX, ARRAY4(EBP, -13))
   XOR(EDX, ARRAY4(EBP, -14))

   XOR(EAX, ARRAY4(EBP, -13))
   XOR(EBX, ARRAY4(EBP, -14))
   XOR(ECX, ARRAY4(EBP, -15))
   XOR(EDX, ARRAY4(EBP, -16))

   ROTL_IMM(EDX, 1)
   ROTL_IMM(ECX, 1)
   ROTL_IMM(EBX, 1)
   XOR(EAX, EDX)
   ROTL_IMM(EAX, 1)

   ASSIGN(ARRAY4(EBP, 0), EDX)
   ASSIGN(ARRAY4(EBP, 1), ECX)
   ASSIGN(ARRAY4(EBP, 2), EBX)
   ASSIGN(ARRAY4(EBP, 3), EAX)

   ADD_IMM(EBP, 16)
LOOP_UNTIL_EQ(ESI, 80, .EXPANSION)

   ASSIGN(EBP, ARG(1))
   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))
   ASSIGN(ESI, ARRAY4(EBP, 4))

#define MAGIC1 0x5A827999
#define MAGIC2 0x6ED9EBA1
#define MAGIC3 0x8F1BBCDC
#define MAGIC4 0xCA62C1D6

#define T1 EDI
#define T2 EBP

#define F1(A, B, C, D, E, N)          \
   ROTL_IMM(A, 5)                   ; \
   ASSIGN(T2, C)                    ; \
   XOR(T2, D)                       ; \
   AND(T2, B)                       ; \
   XOR(T2, D)                       ; \
   ADD(E, T1)                       ; \
   ASSIGN(T1, ARG(3))               ; \
   ROTR_IMM(B, 2)                   ; \
   ADD3_IMM(E, A, MAGIC1)           ; \
   ADD(E, T2)                       ; \
   ASSIGN(T1, ARRAY4(T1, (N+1)))    ; \
   ROTR_IMM(A, 5)                   ;

#define F2_4(A, B, C, D, E, N, MAGIC) \
   ROTL_IMM(A, 5)                   ; \
   ASSIGN(T2, D)                    ; \
   XOR(T2, C)                       ; \
   XOR(T2, B)                       ; \
   ADD(E, T1)                       ; \
   ASSIGN(T1, ARG(3))               ; \
   ROTR_IMM(B, 2)                   ; \
   ADD3_IMM(E, A, MAGIC)            ; \
   ADD(E, T2)                       ; \
   ASSIGN(T1, ARRAY4(T1, (N+1)))    ; \
   ROTR_IMM(A, 5)                   ;

#define F3(A, B, C, D, E, N)          \
   ROTL_IMM(A, 5)                   ; \
   ASSIGN(T2, B)                    ; \
   OR(T2, C)                        ; \
   AND(T2, D)                       ; \
   ADD(E, T1)                       ; \
   ASSIGN(T1, B)                    ; \
   AND(T1, C)                       ; \
   OR(T2, T1)                       ; \
   ASSIGN(T1, ARG(3))               ; \
   ROTR_IMM(B, 2)                   ; \
   ADD3_IMM(E, A, MAGIC3)           ; \
   ADD(E, T2)                       ; \
   ASSIGN(T1, ARRAY4(T1, (N+1)))    ; \
   ROTR_IMM(A, 5)                   ;

#define F2(A, B, C, D, E, MSG) \
   F2_4(A, B, C, D, E, MSG, MAGIC2)

#define F4(A, B, C, D, E, MSG) \
   F2_4(A, B, C, D, E, MSG, MAGIC4)

   ASSIGN(T1, ARG(3))
   ASSIGN(T1, ARRAY4(T1, 0))

   /* First Round */
   F1(EAX, EBX, ECX, EDX, ESI,  0)
   F1(ESI, EAX, EBX, ECX, EDX,  1)
   F1(EDX, ESI, EAX, EBX, ECX,  2)
   F1(ECX, EDX, ESI, EAX, EBX,  3)
   F1(EBX, ECX, EDX, ESI, EAX,  4)

   F1(EAX, EBX, ECX, EDX, ESI,  5)
   F1(ESI, EAX, EBX, ECX, EDX,  6)
   F1(EDX, ESI, EAX, EBX, ECX,  7)
   F1(ECX, EDX, ESI, EAX, EBX,  8)
   F1(EBX, ECX, EDX, ESI, EAX,  9)

   F1(EAX, EBX, ECX, EDX, ESI, 10)
   F1(ESI, EAX, EBX, ECX, EDX, 11)
   F1(EDX, ESI, EAX, EBX, ECX, 12)
   F1(ECX, EDX, ESI, EAX, EBX, 13)
   F1(EBX, ECX, EDX, ESI, EAX, 14)

   F1(EAX, EBX, ECX, EDX, ESI, 15)
   F1(ESI, EAX, EBX, ECX, EDX, 16)
   F1(EDX, ESI, EAX, EBX, ECX, 17)
   F1(ECX, EDX, ESI, EAX, EBX, 18)
   F1(EBX, ECX, EDX, ESI, EAX, 19)

   /* Second Round */
   F2(EAX, EBX, ECX, EDX, ESI, 20)
   F2(ESI, EAX, EBX, ECX, EDX, 21)
   F2(EDX, ESI, EAX, EBX, ECX, 22)
   F2(ECX, EDX, ESI, EAX, EBX, 23)
   F2(EBX, ECX, EDX, ESI, EAX, 24)

   F2(EAX, EBX, ECX, EDX, ESI, 25)
   F2(ESI, EAX, EBX, ECX, EDX, 26)
   F2(EDX, ESI, EAX, EBX, ECX, 27)
   F2(ECX, EDX, ESI, EAX, EBX, 28)
   F2(EBX, ECX, EDX, ESI, EAX, 29)

   F2(EAX, EBX, ECX, EDX, ESI, 30)
   F2(ESI, EAX, EBX, ECX, EDX, 31)
   F2(EDX, ESI, EAX, EBX, ECX, 32)
   F2(ECX, EDX, ESI, EAX, EBX, 33)
   F2(EBX, ECX, EDX, ESI, EAX, 34)

   F2(EAX, EBX, ECX, EDX, ESI, 35)
   F2(ESI, EAX, EBX, ECX, EDX, 36)
   F2(EDX, ESI, EAX, EBX, ECX, 37)
   F2(ECX, EDX, ESI, EAX, EBX, 38)
   F2(EBX, ECX, EDX, ESI, EAX, 39)

   /* Third Round */
   F3(EAX, EBX, ECX, EDX, ESI, 40)
   F3(ESI, EAX, EBX, ECX, EDX, 41)
   F3(EDX, ESI, EAX, EBX, ECX, 42)
   F3(ECX, EDX, ESI, EAX, EBX, 43)
   F3(EBX, ECX, EDX, ESI, EAX, 44)

   F3(EAX, EBX, ECX, EDX, ESI, 45)
   F3(ESI, EAX, EBX, ECX, EDX, 46)
   F3(EDX, ESI, EAX, EBX, ECX, 47)
   F3(ECX, EDX, ESI, EAX, EBX, 48)
   F3(EBX, ECX, EDX, ESI, EAX, 49)

   F3(EAX, EBX, ECX, EDX, ESI, 50)
   F3(ESI, EAX, EBX, ECX, EDX, 51)
   F3(EDX, ESI, EAX, EBX, ECX, 52)
   F3(ECX, EDX, ESI, EAX, EBX, 53)
   F3(EBX, ECX, EDX, ESI, EAX, 54)

   F3(EAX, EBX, ECX, EDX, ESI, 55)
   F3(ESI, EAX, EBX, ECX, EDX, 56)
   F3(EDX, ESI, EAX, EBX, ECX, 57)
   F3(ECX, EDX, ESI, EAX, EBX, 58)
   F3(EBX, ECX, EDX, ESI, EAX, 59)

   /* Fourth Round */
   F4(EAX, EBX, ECX, EDX, ESI, 60)
   F4(ESI, EAX, EBX, ECX, EDX, 61)
   F4(EDX, ESI, EAX, EBX, ECX, 62)
   F4(ECX, EDX, ESI, EAX, EBX, 63)
   F4(EBX, ECX, EDX, ESI, EAX, 64)

   F4(EAX, EBX, ECX, EDX, ESI, 65)
   F4(ESI, EAX, EBX, ECX, EDX, 66)
   F4(EDX, ESI, EAX, EBX, ECX, 67)
   F4(ECX, EDX, ESI, EAX, EBX, 68)
   F4(EBX, ECX, EDX, ESI, EAX, 69)

   F4(EAX, EBX, ECX, EDX, ESI, 70)
   F4(ESI, EAX, EBX, ECX, EDX, 71)
   F4(EDX, ESI, EAX, EBX, ECX, 72)
   F4(ECX, EDX, ESI, EAX, EBX, 73)
   F4(EBX, ECX, EDX, ESI, EAX, 74)

   F4(EAX, EBX, ECX, EDX, ESI, 75)
   F4(ESI, EAX, EBX, ECX, EDX, 76)
   F4(EDX, ESI, EAX, EBX, ECX, 77)
   F4(ECX, EDX, ESI, EAX, EBX, 78)
   F4(EBX, ECX, EDX, ESI, EAX, 0)

   ASSIGN(EBP, ARG(1))
   ADD(ARRAY4(EBP, 0), EAX)
   ADD(ARRAY4(EBP, 1), EBX)
   ADD(ARRAY4(EBP, 2), ECX)
   ADD(ARRAY4(EBP, 3), EDX)
   ADD(ARRAY4(EBP, 4), ESI)

   RESTORE_REGS()
END_FUNCTION(sha160_core)
