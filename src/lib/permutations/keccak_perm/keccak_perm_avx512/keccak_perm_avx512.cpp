/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/internal/isa_extn.h>
#include <immintrin.h>

namespace Botan {

namespace {

void BOTAN_FN_ISA_AVX512 Keccak_Permutation_round_avx512(__m128i T[25], const __m128i A[25], uint64_t RC) {
   constexpr uint8_t xor_not_and = 0b11010010;  // (x ^ (~y & z))

   const __m128i A0 = A[0];
   const __m128i A1 = A[1];
   const __m128i A2 = A[2];
   const __m128i A3 = A[3];
   const __m128i A4 = A[4];
   const __m128i A5 = A[5];
   const __m128i A6 = A[6];
   const __m128i A7 = A[7];
   const __m128i A8 = A[8];
   const __m128i A9 = A[9];
   const __m128i A10 = A[10];
   const __m128i A11 = A[11];
   const __m128i A12 = A[12];
   const __m128i A13 = A[13];
   const __m128i A14 = A[14];
   const __m128i A15 = A[15];
   const __m128i A16 = A[16];
   const __m128i A17 = A[17];
   const __m128i A18 = A[18];
   const __m128i A19 = A[19];
   const __m128i A20 = A[20];
   const __m128i A21 = A[21];
   const __m128i A22 = A[22];
   const __m128i A23 = A[23];
   const __m128i A24 = A[24];

   const auto C0 = A0 ^ A5 ^ A10 ^ A15 ^ A20;
   const auto C1 = A1 ^ A6 ^ A11 ^ A16 ^ A21;
   const auto C2 = A2 ^ A7 ^ A12 ^ A17 ^ A22;
   const auto C3 = A3 ^ A8 ^ A13 ^ A18 ^ A23;
   const auto C4 = A4 ^ A9 ^ A14 ^ A19 ^ A24;

   const auto D0 = _mm_rol_epi64(C0, 1) ^ C3;
   const auto D1 = _mm_rol_epi64(C1, 1) ^ C4;
   const auto D2 = _mm_rol_epi64(C2, 1) ^ C0;
   const auto D3 = _mm_rol_epi64(C3, 1) ^ C1;
   const auto D4 = _mm_rol_epi64(C4, 1) ^ C2;

   const auto B00 = A0 ^ D1;
   const auto B01 = _mm_rol_epi64(A6 ^ D2, 44);
   const auto B02 = _mm_rol_epi64(A12 ^ D3, 43);
   const auto B03 = _mm_rol_epi64(A18 ^ D4, 21);
   const auto B04 = _mm_rol_epi64(A24 ^ D0, 14);
   T[0] = _mm_ternarylogic_epi64(B00, B01, B02, xor_not_and) ^ _mm_set1_epi64x(RC);
   T[1] = _mm_ternarylogic_epi64(B01, B02, B03, xor_not_and);
   T[2] = _mm_ternarylogic_epi64(B02, B03, B04, xor_not_and);
   T[3] = _mm_ternarylogic_epi64(B03, B04, B00, xor_not_and);
   T[4] = _mm_ternarylogic_epi64(B04, B00, B01, xor_not_and);

   const auto B05 = _mm_rol_epi64(A3 ^ D4, 28);
   const auto B06 = _mm_rol_epi64(A9 ^ D0, 20);
   const auto B07 = _mm_rol_epi64(A10 ^ D1, 3);
   const auto B08 = _mm_rol_epi64(A16 ^ D2, 45);
   const auto B09 = _mm_rol_epi64(A22 ^ D3, 61);
   T[5] = _mm_ternarylogic_epi64(B05, B06, B07, xor_not_and);
   T[6] = _mm_ternarylogic_epi64(B06, B07, B08, xor_not_and);
   T[7] = _mm_ternarylogic_epi64(B07, B08, B09, xor_not_and);
   T[8] = _mm_ternarylogic_epi64(B08, B09, B05, xor_not_and);
   T[9] = _mm_ternarylogic_epi64(B09, B05, B06, xor_not_and);

   const auto B10 = _mm_rol_epi64(A1 ^ D2, 1);
   const auto B11 = _mm_rol_epi64(A7 ^ D3, 6);
   const auto B12 = _mm_rol_epi64(A13 ^ D4, 25);
   const auto B13 = _mm_rol_epi64(A19 ^ D0, 8);
   const auto B14 = _mm_rol_epi64(A20 ^ D1, 18);
   T[10] = _mm_ternarylogic_epi64(B10, B11, B12, xor_not_and);
   T[11] = _mm_ternarylogic_epi64(B11, B12, B13, xor_not_and);
   T[12] = _mm_ternarylogic_epi64(B12, B13, B14, xor_not_and);
   T[13] = _mm_ternarylogic_epi64(B13, B14, B10, xor_not_and);
   T[14] = _mm_ternarylogic_epi64(B14, B10, B11, xor_not_and);

   const auto B15 = _mm_rol_epi64(A4 ^ D0, 27);
   const auto B16 = _mm_rol_epi64(A5 ^ D1, 36);
   const auto B17 = _mm_rol_epi64(A11 ^ D2, 10);
   const auto B18 = _mm_rol_epi64(A17 ^ D3, 15);
   const auto B19 = _mm_rol_epi64(A23 ^ D4, 56);
   T[15] = _mm_ternarylogic_epi64(B15, B16, B17, xor_not_and);
   T[16] = _mm_ternarylogic_epi64(B16, B17, B18, xor_not_and);
   T[17] = _mm_ternarylogic_epi64(B17, B18, B19, xor_not_and);
   T[18] = _mm_ternarylogic_epi64(B18, B19, B15, xor_not_and);
   T[19] = _mm_ternarylogic_epi64(B19, B15, B16, xor_not_and);

   const auto B20 = _mm_rol_epi64(A2 ^ D3, 62);
   const auto B21 = _mm_rol_epi64(A8 ^ D4, 55);
   const auto B22 = _mm_rol_epi64(A14 ^ D0, 39);
   const auto B23 = _mm_rol_epi64(A15 ^ D1, 41);
   const auto B24 = _mm_rol_epi64(A21 ^ D2, 2);
   T[20] = _mm_ternarylogic_epi64(B20, B21, B22, xor_not_and);
   T[21] = _mm_ternarylogic_epi64(B21, B22, B23, xor_not_and);
   T[22] = _mm_ternarylogic_epi64(B22, B23, B24, xor_not_and);
   T[23] = _mm_ternarylogic_epi64(B23, B24, B20, xor_not_and);
   T[24] = _mm_ternarylogic_epi64(B24, B20, B21, xor_not_and);
}

}  // namespace

void BOTAN_FN_ISA_AVX512 Keccak_Permutation::permute_avx512() {
   static const uint64_t RC[24] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                                   0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                                   0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                                   0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                                   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

   __m128i X[25];
   __m128i Y[25];

   for(size_t i = 0; i != 25; ++i) {
      X[i] = _mm_set1_epi64x(state()[i]);
   }

   for(size_t i = 0; i != 24; i += 2) {
      Keccak_Permutation_round_avx512(Y, X, RC[i + 0]);
      Keccak_Permutation_round_avx512(X, Y, RC[i + 1]);
   }

   for(size_t i = 0; i != 25; ++i) {
      state()[i] = _mm_extract_epi64(X[i], 0);
   }
}

}  // namespace Botan
