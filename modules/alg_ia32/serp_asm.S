/*************************************************
* Serpent Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(serp_asm.S)

#define SBOX1(A, B, C, D, T)       \
   XOR(D, A)                     ; \
   ASSIGN(T, B)                  ; \
   AND(B, D)                     ; \
   XOR(T, C)                     ; \
   XOR(B, A)                     ; \
   OR(A, D)                      ; \
   XOR(A, T)                     ; \
   XOR(T, D)                     ; \
   XOR(D, C)                     ; \
   OR(C, B)                      ; \
   XOR(C, T)                     ; \
   NOT(T)                        ; \
   OR(T, B)                      ; \
   XOR(B, D)                     ; \
   XOR(B, T)                     ; \
   OR(D, A)                      ; \
   XOR(B, D)                     ; \
   XOR(T, D)                     ; \
   ASSIGN(D, A)                  ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, T)                  ;

#define SBOX2(A, B, C, D, T)       \
   NOT(A)                        ; \
   NOT(C)                        ; \
   ASSIGN(T, A)                  ; \
   AND(A, B)                     ; \
   XOR(C, A)                     ; \
   OR(A, D)                      ; \
   XOR(D, C)                     ; \
   XOR(B, A)                     ; \
   XOR(A, T)                     ; \
   OR(T, B)                      ; \
   XOR(B, D)                     ; \
   OR(C, A)                      ; \
   AND(C, T)                     ; \
   XOR(A, B)                     ; \
   AND(B, C)                     ; \
   XOR(B, A)                     ; \
   AND(A, C)                     ; \
   XOR(T, A)                     ; \
   ASSIGN(A, C)                  ; \
   ASSIGN(C, D)                  ; \
   ASSIGN(D, B)                  ; \
   ASSIGN(B, T)                  ;

#define SBOX3(A, B, C, D, T)       \
   ASSIGN(T, A)                  ; \
   AND(A, C)                     ; \
   XOR(A, D)                     ; \
   XOR(C, B)                     ; \
   XOR(C, A)                     ; \
   OR(D, T)                      ; \
   XOR(D, B)                     ; \
   XOR(T, C)                     ; \
   ASSIGN(B, D)                  ; \
   OR(D, T)                      ; \
   XOR(D, A)                     ; \
   AND(A, B)                     ; \
   XOR(T, A)                     ; \
   XOR(B, D)                     ; \
   XOR(B, T)                     ; \
   NOT(T)                        ; \
   ASSIGN(A, C)                  ; \
   ASSIGN(C, B)                  ; \
   ASSIGN(B, D)                  ; \
   ASSIGN(D, T)                  ;

#define SBOX4(A, B, C, D, T)       \
   ASSIGN(T, A)                  ; \
   OR(A, D)                      ; \
   XOR(D, B)                     ; \
   AND(B, T)                     ; \
   XOR(T, C)                     ; \
   XOR(C, D)                     ; \
   AND(D, A)                     ; \
   OR(T, B)                      ; \
   XOR(D, T)                     ; \
   XOR(A, B)                     ; \
   AND(T, A)                     ; \
   XOR(B, D)                     ; \
   XOR(T, C)                     ; \
   OR(B, A)                      ; \
   XOR(B, C)                     ; \
   XOR(A, D)                     ; \
   ASSIGN(C, B)                  ; \
   OR(B, D)                      ; \
   XOR(B, A)                     ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, C)                  ; \
   ASSIGN(C, D)                  ; \
   ASSIGN(D, T)                  ; \

#define SBOX5(A, B, C, D, T)       \
   XOR(B, D)                     ; \
   NOT(D)                        ; \
   XOR(C, D)                     ; \
   XOR(D, A)                     ; \
   ASSIGN(T, B)                  ; \
   AND(B, D)                     ; \
   XOR(B, C)                     ; \
   XOR(T, D)                     ; \
   XOR(A, T)                     ; \
   AND(C, T)                     ; \
   XOR(C, A)                     ; \
   AND(A, B)                     ; \
   XOR(D, A)                     ; \
   OR(T, B)                      ; \
   XOR(T, A)                     ; \
   OR(A, D)                      ; \
   XOR(A, C)                     ; \
   AND(C, D)                     ; \
   NOT(A)                        ; \
   XOR(T, C)                     ; \
   ASSIGN(C, A)                  ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, T)                  ;

#define SBOX6(A, B, C, D, T)       \
   XOR(A, B)                     ; \
   XOR(B, D)                     ; \
   NOT(D)                        ; \
   ASSIGN(T, B)                  ; \
   AND(B, A)                     ; \
   XOR(C, D)                     ; \
   XOR(B, C)                     ; \
   OR(C, T)                      ; \
   XOR(T, D)                     ; \
   AND(D, B)                     ; \
   XOR(D, A)                     ; \
   XOR(T, B)                     ; \
   XOR(T, C)                     ; \
   XOR(C, A)                     ; \
   AND(A, D)                     ; \
   NOT(C)                        ; \
   XOR(A, T)                     ; \
   OR(T, D)                      ; \
   XOR(T, C)                     ; \
   ASSIGN(C, A)                  ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, D)                  ; \
   ASSIGN(D, T)                  ; \

#define SBOX7(A, B, C, D, T)       \
   NOT(C)                        ; \
   ASSIGN(T, D)                  ; \
   AND(D, A)                     ; \
   XOR(A, T)                     ; \
   XOR(D, C)                     ; \
   OR(C, T)                      ; \
   XOR(B, D)                     ; \
   XOR(C, A)                     ; \
   OR(A, B)                      ; \
   XOR(C, B)                     ; \
   XOR(T, A)                     ; \
   OR(A, D)                      ; \
   XOR(A, C)                     ; \
   XOR(T, D)                     ; \
   XOR(T, A)                     ; \
   NOT(D)                        ; \
   AND(C, T)                     ; \
   XOR(C, D)                     ; \
   ASSIGN(D, C)                  ; \
   ASSIGN(C, T)                  ;

#define SBOX8(A, B, C, D, T)       \
   ASSIGN(T, B)                  ; \
   OR(B, C)                      ; \
   XOR(B, D)                     ; \
   XOR(T, C)                     ; \
   XOR(C, B)                     ; \
   OR(D, T)                      ; \
   AND(D, A)                     ; \
   XOR(T, C)                     ; \
   XOR(D, B)                     ; \
   OR(B, T)                      ; \
   XOR(B, A)                     ; \
   OR(A, T)                      ; \
   XOR(A, C)                     ; \
   XOR(B, T)                     ; \
   XOR(C, B)                     ; \
   AND(B, A)                     ; \
   XOR(B, T)                     ; \
   NOT(C)                        ; \
   OR(C, A)                      ; \
   XOR(T, C)                     ; \
   ASSIGN(C, B)                  ; \
   ASSIGN(B, D)                  ; \
   ASSIGN(D, A)                  ; \
   ASSIGN(A, T)                  ; \

#define TRANSFORM(A, B, C, D, T)   \
   ROTL_IMM(A, 13)               ; \
   ROTL_IMM(C, 3)                ; \
   XOR(B, A)                     ; \
   XOR(B, C)                     ; \
   XOR(D, C)                     ; \
   ASSIGN(T, A)                  ; \
   SHL_IMM(T, 3)                 ; \
   XOR(D, T)                     ; \
   ROTL_IMM(B, 1)                ; \
   ROTL_IMM(D, 7)                ; \
   XOR(A, B)                     ; \
   XOR(A, D)                     ; \
   XOR(C, D)                     ; \
   ASSIGN(T, B)                  ; \
   SHL_IMM(T, 7)                 ; \
   XOR(C, T)                     ; \
   ROTL_IMM(A, 5)                ; \
   ROTL_IMM(C, 22)               ;

#define KEY_XOR(A, B, C, D, N)     \
   XOR(A, ARRAY4(EDI, (4*N  )))  ; \
   XOR(B, ARRAY4(EDI, (4*N+1)))  ; \
   XOR(C, ARRAY4(EDI, (4*N+2)))  ; \
   XOR(D, ARRAY4(EDI, (4*N+3)))  ; \

START_FUNCTION(serpent_encrypt)
   SPILL_REGS()

#define PUSHED 4

   ASSIGN(EBP, ARG(1)) /* input block */
   ASSIGN(EDI, ARG(3)) /* round keys */

   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

   ZEROIZE(EBP)

#define ROUND(A, B, C, D, T, N, SBOX) \
   KEY_XOR(A, B, C, D, N) \
   SBOX(A, B, C, D, T) \
   TRANSFORM(A, B, C, D, T)

   ROUND(EAX, EBX, ECX, EDX, EBP,  0, SBOX1)
   ROUND(EAX, EBX, ECX, EDX, EBP,  1, SBOX2)
   ROUND(EAX, EBX, ECX, EDX, EBP,  2, SBOX3)
   ROUND(EAX, EBX, ECX, EDX, EBP,  3, SBOX4)
   ROUND(EAX, EBX, ECX, EDX, EBP,  4, SBOX5)
   ROUND(EAX, EBX, ECX, EDX, EBP,  5, SBOX6)
   ROUND(EAX, EBX, ECX, EDX, EBP,  6, SBOX7)
   ROUND(EAX, EBX, ECX, EDX, EBP,  7, SBOX8)

   ROUND(EAX, EBX, ECX, EDX, EBP,  8, SBOX1)
   ROUND(EAX, EBX, ECX, EDX, EBP,  9, SBOX2)
   ROUND(EAX, EBX, ECX, EDX, EBP, 10, SBOX3)
   ROUND(EAX, EBX, ECX, EDX, EBP, 11, SBOX4)
   ROUND(EAX, EBX, ECX, EDX, EBP, 12, SBOX5)
   ROUND(EAX, EBX, ECX, EDX, EBP, 13, SBOX6)
   ROUND(EAX, EBX, ECX, EDX, EBP, 14, SBOX7)
   ROUND(EAX, EBX, ECX, EDX, EBP, 15, SBOX8)

   ROUND(EAX, EBX, ECX, EDX, EBP, 16, SBOX1)
   ROUND(EAX, EBX, ECX, EDX, EBP, 17, SBOX2)
   ROUND(EAX, EBX, ECX, EDX, EBP, 18, SBOX3)
   ROUND(EAX, EBX, ECX, EDX, EBP, 19, SBOX4)
   ROUND(EAX, EBX, ECX, EDX, EBP, 20, SBOX5)
   ROUND(EAX, EBX, ECX, EDX, EBP, 21, SBOX6)
   ROUND(EAX, EBX, ECX, EDX, EBP, 22, SBOX7)
   ROUND(EAX, EBX, ECX, EDX, EBP, 23, SBOX8)

   ROUND(EAX, EBX, ECX, EDX, EBP, 24, SBOX1)
   ROUND(EAX, EBX, ECX, EDX, EBP, 25, SBOX2)
   ROUND(EAX, EBX, ECX, EDX, EBP, 26, SBOX3)
   ROUND(EAX, EBX, ECX, EDX, EBP, 27, SBOX4)
   ROUND(EAX, EBX, ECX, EDX, EBP, 28, SBOX5)
   ROUND(EAX, EBX, ECX, EDX, EBP, 29, SBOX6)
   ROUND(EAX, EBX, ECX, EDX, EBP, 30, SBOX7)

   KEY_XOR(EAX, EBX, ECX, EDX, 31)
   SBOX8(EAX, EBX, ECX, EDX, EBP)
   KEY_XOR(EAX, EBX, ECX, EDX, 32)

   ASSIGN(EBP, ARG(2)) /* output block */
   ASSIGN(ARRAY4(EBP, 0), EAX)
   ASSIGN(ARRAY4(EBP, 1), EBX)
   ASSIGN(ARRAY4(EBP, 2), ECX)
   ASSIGN(ARRAY4(EBP, 3), EDX)

   RESTORE_REGS()
END_FUNCTION(serpent_encrypt)
