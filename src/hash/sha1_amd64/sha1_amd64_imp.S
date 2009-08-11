/*
* SHA-160 Source File
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(sha1_amd64.S)

START_FUNCTION(botan_sha160_amd64_compress)

#define DIGEST_ARR %rdi
#define INPUT %rsi
#define W %rdx
#define LOOP_CTR %eax

#define A %r8d
#define B %r9d
#define C %r10d
#define D %r11d
#define E %ecx

   ZEROIZE(LOOP_CTR)

ALIGN;
.LOOP_LOAD_INPUT:
   addl $8, %eax

   movq ARRAY8(INPUT, 0), %r8
   movq ARRAY8(INPUT, 1), %r9
   movq ARRAY8(INPUT, 2), %r10
   movq ARRAY8(INPUT, 3), %r11

   bswap %r8
   bswap %r9
   bswap %r10
   bswap %r11

   rolq $32, %r8
   rolq $32, %r9
   rolq $32, %r10
   rolq $32, %r11

   movq %r8, ARRAY8(W, 0)
   movq %r9, ARRAY8(W, 1)
   movq %r10, ARRAY8(W, 2)
   movq %r11, ARRAY8(W, 3)

   addq $32, W
   addq $32, INPUT

   cmp IMM(16), LOOP_CTR
   jne .LOOP_LOAD_INPUT

/*
#define A %r8d
#define B %r9d
#define C %r10d
#define D %r11d
#define E %ecx
*/

ALIGN;
.LOOP_EXPANSION:
   addl $4, LOOP_CTR

   ZEROIZE(A)
   ASSIGN(B, ARRAY4(W, -1))
   ASSIGN(C, ARRAY4(W, -2))
   ASSIGN(D, ARRAY4(W, -3))

   XOR(A, ARRAY4(W, -5))
   XOR(B, ARRAY4(W, -6))
   XOR(C, ARRAY4(W, -7))
   XOR(D, ARRAY4(W, -8))

   XOR(A, ARRAY4(W, -11))
   XOR(B, ARRAY4(W, -12))
   XOR(C, ARRAY4(W, -13))
   XOR(D, ARRAY4(W, -14))

   XOR(A, ARRAY4(W, -13))
   XOR(B, ARRAY4(W, -14))
   XOR(C, ARRAY4(W, -15))
   XOR(D, ARRAY4(W, -16))

   ROTL_IMM(D, 1)
   ROTL_IMM(C, 1)
   ROTL_IMM(B, 1)
   XOR(A, D)
   ROTL_IMM(A, 1)

   ASSIGN(ARRAY4(W, 0), D)
   ASSIGN(ARRAY4(W, 1), C)
   ASSIGN(ARRAY4(W, 2), B)
   ASSIGN(ARRAY4(W, 3), A)

   addq $16, W
   cmp IMM(80), LOOP_CTR
   jne .LOOP_EXPANSION

   subq $320, W

#define MAGIC1 0x5A827999
#define MAGIC2 0x6ED9EBA1
#define MAGIC3 0x8F1BBCDC
#define MAGIC4 0xCA62C1D6

#define T %esi
#define T2 %eax

#define F1(A, B, C, D, E, F, N)       \
   ASSIGN(T2, ARRAY4(W, N))         ; \
   ASSIGN(A, F)                     ; \
   ROTL_IMM(F, 5)                   ; \
   ADD(F, E)                        ; \
   ASSIGN(E, C)                     ; \
   XOR(E, D)                        ; \
   ADD3_IMM(F, T2, MAGIC1)          ; \
   AND(E, B)                        ; \
   XOR(E, D)                        ; \
   ROTR_IMM(B, 2)                   ; \
   ADD(E, F)                        ;

#define F2_4(A, B, C, D, E, F, N, MAGIC) \
   ASSIGN(T2, ARRAY4(W, N))         ; \
   ASSIGN(A, F)                     ; \
   ROTL_IMM(F, 5)                   ; \
   ADD(F, E)                        ; \
   ASSIGN(E, B)                     ; \
   XOR(E, C)                        ; \
   ADD3_IMM(F, T2, MAGIC)           ; \
   XOR(E, D)                        ; \
   ROTR_IMM(B, 2)                   ; \
   ADD(E, F)                        ;

#define F3(A, B, C, D, E, F, N)       \
   ASSIGN(T2, ARRAY4(W, N))         ; \
   ASSIGN(A, F)                     ; \
   ROTL_IMM(F, 5)                   ; \
   ADD(F, E)                        ; \
   ASSIGN(E, B)                     ; \
   OR(E, C)                         ; \
   AND(E, D)                        ; \
   ADD3_IMM(F, T2, MAGIC3)          ; \
   ASSIGN(T2, B)                    ; \
   AND(T2, C)                       ; \
   OR(E, T2)                        ; \
   ROTR_IMM(B, 2)                   ; \
   ADD(E, F)                        ;

#define F2(A, B, C, D, E, F, W) \
   F2_4(A, B, C, D, E, F, W, MAGIC2)

#define F4(A, B, C, D, E, F, W) \
   F2_4(A, B, C, D, E, F, W, MAGIC4)

   ASSIGN(T, ARRAY4(DIGEST_ARR, 0))
   ASSIGN(B, ARRAY4(DIGEST_ARR, 1))
   ASSIGN(C, ARRAY4(DIGEST_ARR, 2))
   ASSIGN(D, ARRAY4(DIGEST_ARR, 3))
   ASSIGN(E, ARRAY4(DIGEST_ARR, 4))

   /* First Round */
   F1(A, B, C, D, E, T, 0)
   F1(T, A, B, C, D, E, 1)
   F1(E, T, A, B, C, D, 2)
   F1(D, E, T, A, B, C, 3)
   F1(C, D, E, T, A, B, 4)
   F1(B, C, D, E, T, A, 5)
   F1(A, B, C, D, E, T, 6)
   F1(T, A, B, C, D, E, 7)
   F1(E, T, A, B, C, D, 8)
   F1(D, E, T, A, B, C, 9)
   F1(C, D, E, T, A, B, 10)
   F1(B, C, D, E, T, A, 11)
   F1(A, B, C, D, E, T, 12)
   F1(T, A, B, C, D, E, 13)
   F1(E, T, A, B, C, D, 14)
   F1(D, E, T, A, B, C, 15)
   F1(C, D, E, T, A, B, 16)
   F1(B, C, D, E, T, A, 17)
   F1(A, B, C, D, E, T, 18)
   F1(T, A, B, C, D, E, 19)

   /* Second Round */
   F2(E, T, A, B, C, D, 20)
   F2(D, E, T, A, B, C, 21)
   F2(C, D, E, T, A, B, 22)
   F2(B, C, D, E, T, A, 23)
   F2(A, B, C, D, E, T, 24)
   F2(T, A, B, C, D, E, 25)
   F2(E, T, A, B, C, D, 26)
   F2(D, E, T, A, B, C, 27)
   F2(C, D, E, T, A, B, 28)
   F2(B, C, D, E, T, A, 29)
   F2(A, B, C, D, E, T, 30)
   F2(T, A, B, C, D, E, 31)
   F2(E, T, A, B, C, D, 32)
   F2(D, E, T, A, B, C, 33)
   F2(C, D, E, T, A, B, 34)
   F2(B, C, D, E, T, A, 35)
   F2(A, B, C, D, E, T, 36)
   F2(T, A, B, C, D, E, 37)
   F2(E, T, A, B, C, D, 38)
   F2(D, E, T, A, B, C, 39)

   /* Third Round */
   F3(C, D, E, T, A, B, 40)
   F3(B, C, D, E, T, A, 41)
   F3(A, B, C, D, E, T, 42)
   F3(T, A, B, C, D, E, 43)
   F3(E, T, A, B, C, D, 44)
   F3(D, E, T, A, B, C, 45)
   F3(C, D, E, T, A, B, 46)
   F3(B, C, D, E, T, A, 47)
   F3(A, B, C, D, E, T, 48)
   F3(T, A, B, C, D, E, 49)
   F3(E, T, A, B, C, D, 50)
   F3(D, E, T, A, B, C, 51)
   F3(C, D, E, T, A, B, 52)
   F3(B, C, D, E, T, A, 53)
   F3(A, B, C, D, E, T, 54)
   F3(T, A, B, C, D, E, 55)
   F3(E, T, A, B, C, D, 56)
   F3(D, E, T, A, B, C, 57)
   F3(C, D, E, T, A, B, 58)
   F3(B, C, D, E, T, A, 59)

   /* Fourth Round */
   F4(A, B, C, D, E, T, 60)
   F4(T, A, B, C, D, E, 61)
   F4(E, T, A, B, C, D, 62)
   F4(D, E, T, A, B, C, 63)
   F4(C, D, E, T, A, B, 64)
   F4(B, C, D, E, T, A, 65)
   F4(A, B, C, D, E, T, 66)
   F4(T, A, B, C, D, E, 67)
   F4(E, T, A, B, C, D, 68)
   F4(D, E, T, A, B, C, 69)
   F4(C, D, E, T, A, B, 70)
   F4(B, C, D, E, T, A, 71)
   F4(A, B, C, D, E, T, 72)
   F4(T, A, B, C, D, E, 73)
   F4(E, T, A, B, C, D, 74)
   F4(D, E, T, A, B, C, 75)
   F4(C, D, E, T, A, B, 76)
   F4(B, C, D, E, T, A, 77)
   F4(A, B, C, D, E, T, 78)
   F4(T, A, B, C, D, E, 79)

   ADD(ARRAY4(DIGEST_ARR, 0), D)
   ADD(ARRAY4(DIGEST_ARR, 1), T)
   ADD(ARRAY4(DIGEST_ARR, 2), A)
   ADD(ARRAY4(DIGEST_ARR, 3), B)
   ADD(ARRAY4(DIGEST_ARR, 4), C)

END_FUNCTION(botan_sha160_amd64_compress)
