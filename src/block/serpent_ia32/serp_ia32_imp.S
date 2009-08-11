/*
* Serpent Source File
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(serp_ia32.S)

#define SBOX_E1(A, B, C, D, T)     \
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

#define SBOX_E2(A, B, C, D, T)     \
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

#define SBOX_E3(A, B, C, D, T)     \
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

#define SBOX_E4(A, B, C, D, T)     \
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
   ASSIGN(D, T)                  ;

#define SBOX_E5(A, B, C, D, T)     \
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

#define SBOX_E6(A, B, C, D, T)     \
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
   ASSIGN(D, T)                  ;

#define SBOX_E7(A, B, C, D, T)     \
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

#define SBOX_E8(A, B, C, D, T)     \
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
   ASSIGN(A, T)                  ;

#define SBOX_D1(A, B, C, D, T)     \
   NOT(C)                        ; \
   ASSIGN(T, B)                  ; \
   OR(B, A)                      ; \
   NOT(T)                        ; \
   XOR(B, C)                     ; \
   OR(C, T)                      ; \
   XOR(B, D)                     ; \
   XOR(A, T)                     ; \
   XOR(C, A)                     ; \
   AND(A, D)                     ; \
   XOR(T, A)                     ; \
   OR(A, B)                      ; \
   XOR(A, C)                     ; \
   XOR(D, T)                     ; \
   XOR(C, B)                     ; \
   XOR(D, A)                     ; \
   XOR(D, B)                     ; \
   AND(C, D)                     ; \
   XOR(T, C)                     ; \
   ASSIGN(C, B)                  ; \
   ASSIGN(B, T)                  ;

#define SBOX_D2(A, B, C, D, T)     \
   ASSIGN(T, B)                  ; \
   XOR(B, D)                     ; \
   AND(D, B)                     ; \
   XOR(T, C)                     ; \
   XOR(D, A)                     ; \
   OR(A, B)                      ; \
   XOR(C, D)                     ; \
   XOR(A, T)                     ; \
   OR(A, C)                      ; \
   XOR(B, D)                     ; \
   XOR(A, B)                     ; \
   OR(B, D)                      ; \
   XOR(B, A)                     ; \
   NOT(T)                        ; \
   XOR(T, B)                     ; \
   OR(B, A)                      ; \
   XOR(B, A)                     ; \
   OR(B, T)                      ; \
   XOR(D, B)                     ; \
   ASSIGN(B, A)                  ; \
   ASSIGN(A, T)                  ; \
   ASSIGN(T, D)                  ; \
   ASSIGN(D, C)                  ; \
   ASSIGN(C, T)                  ;

#define SBOX_D3(A, B, C, D, T)     \
   XOR(C, D)                     ; \
   XOR(D, A)                     ; \
   ASSIGN(T, D)                  ; \
   AND(D, C)                     ; \
   XOR(D, B)                     ; \
   OR(B, C)                      ; \
   XOR(B, T)                     ; \
   AND(T, D)                     ; \
   XOR(C, D)                     ; \
   AND(T, A)                     ; \
   XOR(T, C)                     ; \
   AND(C, B)                     ; \
   OR(C, A)                      ; \
   NOT(D)                        ; \
   XOR(C, D)                     ; \
   XOR(A, D)                     ; \
   AND(A, B)                     ; \
   XOR(D, T)                     ; \
   XOR(D, A)                     ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, T)                  ;

#define SBOX_D4(A, B, C, D, T)     \
   ASSIGN(T, C)                  ; \
   XOR(C, B)                     ; \
   XOR(A, C)                     ; \
   AND(T, C)                     ; \
   XOR(T, A)                     ; \
   AND(A, B)                     ; \
   XOR(B, D)                     ; \
   OR(D, T)                      ; \
   XOR(C, D)                     ; \
   XOR(A, D)                     ; \
   XOR(B, T)                     ; \
   AND(D, C)                     ; \
   XOR(D, B)                     ; \
   XOR(B, A)                     ; \
   OR(B, C)                      ; \
   XOR(A, D)                     ; \
   XOR(B, T)                     ; \
   XOR(A, B)                     ; \
   ASSIGN(T, A)                  ; \
   ASSIGN(A, C)                  ; \
   ASSIGN(C, D)                  ; \
   ASSIGN(D, T)                  ;

#define SBOX_D5(A, B, C, D, T)     \
   ASSIGN(T, C)                  ; \
   AND(C, D)                     ; \
   XOR(C, B)                     ; \
   OR(B, D)                      ; \
   AND(B, A)                     ; \
   XOR(T, C)                     ; \
   XOR(T, B)                     ; \
   AND(B, C)                     ; \
   NOT(A)                        ; \
   XOR(D, T)                     ; \
   XOR(B, D)                     ; \
   AND(D, A)                     ; \
   XOR(D, C)                     ; \
   XOR(A, B)                     ; \
   AND(C, A)                     ; \
   XOR(D, A)                     ; \
   XOR(C, T)                     ; \
   OR(C, D)                      ; \
   XOR(D, A)                     ; \
   XOR(C, B)                     ; \
   ASSIGN(B, D)                  ; \
   ASSIGN(D, T)                  ;

#define SBOX_D6(A, B, C, D, T)     \
   NOT(B)                        ; \
   ASSIGN(T, D)                  ; \
   XOR(C, B)                     ; \
   OR(D, A)                      ; \
   XOR(D, C)                     ; \
   OR(C, B)                      ; \
   AND(C, A)                     ; \
   XOR(T, D)                     ; \
   XOR(C, T)                     ; \
   OR(T, A)                      ; \
   XOR(T, B)                     ; \
   AND(B, C)                     ; \
   XOR(B, D)                     ; \
   XOR(T, C)                     ; \
   AND(D, T)                     ; \
   XOR(T, B)                     ; \
   XOR(D, T)                     ; \
   NOT(T)                        ; \
   XOR(D, A)                     ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, T)                  ; \
   ASSIGN(T, D)                  ; \
   ASSIGN(D, C)                  ; \
   ASSIGN(C, T)                  ;

#define SBOX_D7(A, B, C, D, T)     \
   XOR(A, C)                     ; \
   ASSIGN(T, C)                  ; \
   AND(C, A)                     ; \
   XOR(T, D)                     ; \
   NOT(C)                        ; \
   XOR(D, B)                     ; \
   XOR(C, D)                     ; \
   OR(T, A)                      ; \
   XOR(A, C)                     ; \
   XOR(D, T)                     ; \
   XOR(T, B)                     ; \
   AND(B, D)                     ; \
   XOR(B, A)                     ; \
   XOR(A, D)                     ; \
   OR(A, C)                      ; \
   XOR(D, B)                     ; \
   XOR(T, A)                     ; \
   ASSIGN(A, B)                  ; \
   ASSIGN(B, C)                  ; \
   ASSIGN(C, T)                  ;

#define SBOX_D8(A, B, C, D, T)     \
   ASSIGN(T, C)                  ; \
   XOR(C, A)                     ; \
   AND(A, D)                     ; \
   OR(T, D)                      ; \
   NOT(C)                        ; \
   XOR(D, B)                     ; \
   OR(B, A)                      ; \
   XOR(A, C)                     ; \
   AND(C, T)                     ; \
   AND(D, T)                     ; \
   XOR(B, C)                     ; \
   XOR(C, A)                     ; \
   OR(A, C)                      ; \
   XOR(T, B)                     ; \
   XOR(A, D)                     ; \
   XOR(D, T)                     ; \
   OR(T, A)                      ; \
   XOR(D, C)                     ; \
   XOR(T, C)                     ; \
   ASSIGN(C, B)                  ; \
   ASSIGN(B, A)                  ; \
   ASSIGN(A, D)                  ; \
   ASSIGN(D, T)                  ;

#define TRANSFORM(A, B, C, D, T)   \
   ROTL_IMM(A, 13)               ; \
   ROTL_IMM(C, 3)                ; \
   SHL2_3(T, A)                  ; \
   XOR(B, A)                     ; \
   XOR(D, C)                     ; \
   XOR(B, C)                     ; \
   XOR(D, T)                     ; \
   ROTL_IMM(B, 1)                ; \
   ROTL_IMM(D, 7)                ; \
   ASSIGN(T, B)                  ; \
   SHL_IMM(T, 7)                 ; \
   XOR(A, B)                     ; \
   XOR(C, D)                     ; \
   XOR(A, D)                     ; \
   XOR(C, T)                     ; \
   ROTL_IMM(A, 5)                ; \
   ROTL_IMM(C, 22)               ;

#define I_TRANSFORM(A, B, C, D, T) \
   ROTR_IMM(C, 22)               ; \
   ROTR_IMM(A, 5)                ; \
   ASSIGN(T, B)                  ; \
   SHL_IMM(T, 7)                 ; \
   XOR(A, B)                     ; \
   XOR(C, D)                     ; \
   XOR(A, D)                     ; \
   XOR(C, T)                     ; \
   ROTR_IMM(D, 7)                ; \
   ROTR_IMM(B, 1)                ; \
   SHL2_3(T, A)                  ; \
   XOR(B, C)                     ; \
   XOR(D, C)                     ; \
   XOR(B, A)                     ; \
   XOR(D, T)                     ; \
   ROTR_IMM(C, 3)                ; \
   ROTR_IMM(A, 13)               ;

#define KEY_XOR(A, B, C, D, N)     \
   XOR(A, ARRAY4(EDI, (4*N  )))  ; \
   XOR(B, ARRAY4(EDI, (4*N+1)))  ; \
   XOR(C, ARRAY4(EDI, (4*N+2)))  ; \
   XOR(D, ARRAY4(EDI, (4*N+3)))  ;

/*
* Serpent Encryption
*/
START_FUNCTION(botan_serpent_ia32_encrypt)
   SPILL_REGS()
#define PUSHED 4

   ASSIGN(EBP, ARG(1)) /* input block */
   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

   ASSIGN(EDI, ARG(3)) /* round keys */
   ZEROIZE(EBP)

#define E_ROUND(A, B, C, D, T, N, SBOX) \
   KEY_XOR(A, B, C, D, N) \
   SBOX(A, B, C, D, T) \
   TRANSFORM(A, B, C, D, T)


   E_ROUND(EAX, EBX, ECX, EDX, EBP,  0, SBOX_E1)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  1, SBOX_E2)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  2, SBOX_E3)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  3, SBOX_E4)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  4, SBOX_E5)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  5, SBOX_E6)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  6, SBOX_E7)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  7, SBOX_E8)

   E_ROUND(EAX, EBX, ECX, EDX, EBP,  8, SBOX_E1)
   E_ROUND(EAX, EBX, ECX, EDX, EBP,  9, SBOX_E2)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 10, SBOX_E3)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 11, SBOX_E4)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 12, SBOX_E5)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 13, SBOX_E6)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 14, SBOX_E7)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 15, SBOX_E8)

   E_ROUND(EAX, EBX, ECX, EDX, EBP, 16, SBOX_E1)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 17, SBOX_E2)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 18, SBOX_E3)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 19, SBOX_E4)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 20, SBOX_E5)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 21, SBOX_E6)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 22, SBOX_E7)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 23, SBOX_E8)

   E_ROUND(EAX, EBX, ECX, EDX, EBP, 24, SBOX_E1)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 25, SBOX_E2)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 26, SBOX_E3)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 27, SBOX_E4)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 28, SBOX_E5)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 29, SBOX_E6)
   E_ROUND(EAX, EBX, ECX, EDX, EBP, 30, SBOX_E7)

   KEY_XOR(EAX, EBX, ECX, EDX, 31)
   SBOX_E8(EAX, EBX, ECX, EDX, EBP)
   KEY_XOR(EAX, EBX, ECX, EDX, 32)

   ASSIGN(EBP, ARG(2)) /* output block */
   ASSIGN(ARRAY4(EBP, 0), EAX)
   ASSIGN(ARRAY4(EBP, 1), EBX)
   ASSIGN(ARRAY4(EBP, 2), ECX)
   ASSIGN(ARRAY4(EBP, 3), EDX)

   RESTORE_REGS()
#undef PUSHED
END_FUNCTION(botan_serpent_ia32_encrypt)

/*
* Serpent Decryption
*/
START_FUNCTION(botan_serpent_ia32_decrypt)
   SPILL_REGS()
#define PUSHED 4

   ASSIGN(EBP, ARG(1)) /* input block */
   ASSIGN(EAX, ARRAY4(EBP, 0))
   ASSIGN(EBX, ARRAY4(EBP, 1))
   ASSIGN(ECX, ARRAY4(EBP, 2))
   ASSIGN(EDX, ARRAY4(EBP, 3))

   ASSIGN(EDI, ARG(3)) /* round keys */

   ZEROIZE(EBP)

#define D_ROUND(A, B, C, D, T, N, SBOX) \
   I_TRANSFORM(A, B, C, D, T) \
   SBOX(A, B, C, D, T) \
   KEY_XOR(A, B, C, D, N) \

   KEY_XOR(EAX, EBX, ECX, EDX, 32)
   SBOX_D8(EAX, EBX, ECX, EDX, EBP)
   KEY_XOR(EAX, EBX, ECX, EDX, 31)

   D_ROUND(EAX, EBX, ECX, EDX, EBP, 30, SBOX_D7)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 29, SBOX_D6)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 28, SBOX_D5)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 27, SBOX_D4)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 26, SBOX_D3)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 25, SBOX_D2)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 24, SBOX_D1)

   D_ROUND(EAX, EBX, ECX, EDX, EBP, 23, SBOX_D8)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 22, SBOX_D7)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 21, SBOX_D6)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 20, SBOX_D5)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 19, SBOX_D4)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 18, SBOX_D3)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 17, SBOX_D2)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 16, SBOX_D1)

   D_ROUND(EAX, EBX, ECX, EDX, EBP, 15, SBOX_D8)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 14, SBOX_D7)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 13, SBOX_D6)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 12, SBOX_D5)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 11, SBOX_D4)
   D_ROUND(EAX, EBX, ECX, EDX, EBP, 10, SBOX_D3)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  9, SBOX_D2)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  8, SBOX_D1)

   D_ROUND(EAX, EBX, ECX, EDX, EBP,  7, SBOX_D8)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  6, SBOX_D7)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  5, SBOX_D6)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  4, SBOX_D5)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  3, SBOX_D4)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  2, SBOX_D3)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  1, SBOX_D2)
   D_ROUND(EAX, EBX, ECX, EDX, EBP,  0, SBOX_D1)

   ASSIGN(EBP, ARG(2)) /* output block */
   ASSIGN(ARRAY4(EBP, 0), EAX)
   ASSIGN(ARRAY4(EBP, 1), EBX)
   ASSIGN(ARRAY4(EBP, 2), ECX)
   ASSIGN(ARRAY4(EBP, 3), EDX)

   RESTORE_REGS()
#undef PUSHED
END_FUNCTION(botan_serpent_ia32_decrypt)

/*
* Serpent Key Schedule
*/
START_FUNCTION(botan_serpent_ia32_key_schedule)
   SPILL_REGS()
#define PUSHED 4

   ASSIGN(EDI, ARG(1)) /* round keys */
   ASSIGN(ESI, IMM(8))
   ADD_IMM(EDI, 32)

START_LOOP(.EXPANSION)
   ASSIGN(EAX, ARRAY4(EDI, -1))
   ASSIGN(EBX, ARRAY4(EDI, -3))
   ASSIGN(ECX, ARRAY4(EDI, -5))
   ASSIGN(EDX, ARRAY4(EDI, -8))

   ASSIGN(EBP, ESI)
   SUB_IMM(EBP, 8)
   XOR(EBP, IMM(0x9E3779B9))
   XOR(EAX, EBX)
   XOR(ECX, EDX)
   XOR(EAX, EBP)
   XOR(EAX, ECX)

   ROTL_IMM(EAX, 11)

   ASSIGN(ARRAY4(EDI, 0), EAX)

   ADD_IMM(ESI, 1)
   ADD_IMM(EDI, 4)
LOOP_UNTIL_EQ(ESI, 140, .EXPANSION)

   ASSIGN(EDI, ARG(1)) /* round keys */

#define LOAD_AND_SBOX(MSG, SBOX)          \
   ASSIGN(EAX, ARRAY4(EDI, (4*MSG+ 8))) ; \
   ASSIGN(EBX, ARRAY4(EDI, (4*MSG+ 9))) ; \
   ASSIGN(ECX, ARRAY4(EDI, (4*MSG+10))) ; \
   ASSIGN(EDX, ARRAY4(EDI, (4*MSG+11))) ; \
   SBOX(EAX, EBX, ECX, EDX, EBP)        ; \
   ASSIGN(ARRAY4(EDI, (4*MSG+ 8)), EAX) ; \
   ASSIGN(ARRAY4(EDI, (4*MSG+ 9)), EBX) ; \
   ASSIGN(ARRAY4(EDI, (4*MSG+10)), ECX) ; \
   ASSIGN(ARRAY4(EDI, (4*MSG+11)), EDX)

   LOAD_AND_SBOX( 0, SBOX_E4)
   LOAD_AND_SBOX( 1, SBOX_E3)
   LOAD_AND_SBOX( 2, SBOX_E2)
   LOAD_AND_SBOX( 3, SBOX_E1)

   LOAD_AND_SBOX( 4, SBOX_E8)
   LOAD_AND_SBOX( 5, SBOX_E7)
   LOAD_AND_SBOX( 6, SBOX_E6)
   LOAD_AND_SBOX( 7, SBOX_E5)
   LOAD_AND_SBOX( 8, SBOX_E4)
   LOAD_AND_SBOX( 9, SBOX_E3)
   LOAD_AND_SBOX(10, SBOX_E2)
   LOAD_AND_SBOX(11, SBOX_E1)

   LOAD_AND_SBOX(12, SBOX_E8)
   LOAD_AND_SBOX(13, SBOX_E7)
   LOAD_AND_SBOX(14, SBOX_E6)
   LOAD_AND_SBOX(15, SBOX_E5)
   LOAD_AND_SBOX(16, SBOX_E4)
   LOAD_AND_SBOX(17, SBOX_E3)
   LOAD_AND_SBOX(18, SBOX_E2)
   LOAD_AND_SBOX(19, SBOX_E1)

   LOAD_AND_SBOX(20, SBOX_E8)
   LOAD_AND_SBOX(21, SBOX_E7)
   LOAD_AND_SBOX(22, SBOX_E6)
   LOAD_AND_SBOX(23, SBOX_E5)
   LOAD_AND_SBOX(24, SBOX_E4)
   LOAD_AND_SBOX(25, SBOX_E3)
   LOAD_AND_SBOX(26, SBOX_E2)
   LOAD_AND_SBOX(27, SBOX_E1)

   LOAD_AND_SBOX(28, SBOX_E8)
   LOAD_AND_SBOX(29, SBOX_E7)
   LOAD_AND_SBOX(30, SBOX_E6)
   LOAD_AND_SBOX(31, SBOX_E5)
   LOAD_AND_SBOX(32, SBOX_E4)

   RESTORE_REGS()
#undef PUSHED
END_FUNCTION(botan_serpent_ia32_key_schedule)
