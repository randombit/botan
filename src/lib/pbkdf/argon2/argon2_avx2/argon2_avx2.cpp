/**
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>

#include <botan/compiler.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x64.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 void blamka_G(SIMD_4x64& A, SIMD_4x64& B, SIMD_4x64& C, SIMD_4x64& D) {
   A += B + SIMD_4x64::mul2_32(A, B);
   D ^= A;
   D = D.rotr<32>();

   C += D + SIMD_4x64::mul2_32(C, D);
   B ^= C;
   B = B.rotr<24>();

   A += B + SIMD_4x64::mul2_32(A, B);
   D ^= A;
   D = D.rotr<16>();

   C += D + SIMD_4x64::mul2_32(C, D);
   B ^= C;
   B = B.rotr<63>();
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 void blamka_R(SIMD_4x64& A, SIMD_4x64& B, SIMD_4x64& C, SIMD_4x64& D) {
   blamka_G(A, B, C, D);

   SIMD_4x64::twist(B, C, D);
   blamka_G(A, B, C, D);
   SIMD_4x64::untwist(B, C, D);
}

}  // namespace

BOTAN_FN_ISA_AVX2 void Argon2::blamka_avx2(uint64_t N[128], uint64_t T[128]) {
   for(size_t i = 0; i != 8; ++i) {
      SIMD_4x64 A = SIMD_4x64::load_le(&N[16 * i + 4 * 0]);
      SIMD_4x64 B = SIMD_4x64::load_le(&N[16 * i + 4 * 1]);
      SIMD_4x64 C = SIMD_4x64::load_le(&N[16 * i + 4 * 2]);
      SIMD_4x64 D = SIMD_4x64::load_le(&N[16 * i + 4 * 3]);

      blamka_R(A, B, C, D);

      A.store_le(&T[16 * i + 4 * 0]);
      B.store_le(&T[16 * i + 4 * 1]);
      C.store_le(&T[16 * i + 4 * 2]);
      D.store_le(&T[16 * i + 4 * 3]);
   }

   for(size_t i = 0; i != 8; ++i) {
      SIMD_4x64 A = SIMD_4x64::load_le2(&T[2 * i + 32 * 0], &T[2 * i + 32 * 0 + 16]);
      SIMD_4x64 B = SIMD_4x64::load_le2(&T[2 * i + 32 * 1], &T[2 * i + 32 * 1 + 16]);
      SIMD_4x64 C = SIMD_4x64::load_le2(&T[2 * i + 32 * 2], &T[2 * i + 32 * 2 + 16]);
      SIMD_4x64 D = SIMD_4x64::load_le2(&T[2 * i + 32 * 3], &T[2 * i + 32 * 3 + 16]);

      blamka_R(A, B, C, D);

      A.store_le2(&T[2 * i + 32 * 0], &T[2 * i + 32 * 0 + 16]);
      B.store_le2(&T[2 * i + 32 * 1], &T[2 * i + 32 * 1 + 16]);
      C.store_le2(&T[2 * i + 32 * 2], &T[2 * i + 32 * 2 + 16]);
      D.store_le2(&T[2 * i + 32 * 3], &T[2 * i + 32 * 3 + 16]);
   }

   for(size_t i = 0; i != 128 / 8; ++i) {
      SIMD_4x64 n0 = SIMD_4x64::load_le(&N[8 * i]);
      SIMD_4x64 n1 = SIMD_4x64::load_le(&N[8 * i + 4]);

      n0 ^= SIMD_4x64::load_le(&T[8 * i]);
      n1 ^= SIMD_4x64::load_le(&T[8 * i + 4]);
      n0.store_le(&N[8 * i]);
      n1.store_le(&N[8 * i + 4]);
   }
}

}  // namespace Botan
