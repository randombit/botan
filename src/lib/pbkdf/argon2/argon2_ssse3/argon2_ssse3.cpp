/**
* (C) 2022 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>

#include <botan/compiler.h>
#include <botan/internal/simd_2x64.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE void blamka_G(SIMD_2x64& A0,
                                 SIMD_2x64& A1,
                                 SIMD_2x64& B0,
                                 SIMD_2x64& B1,
                                 SIMD_2x64& C0,
                                 SIMD_2x64& C1,
                                 SIMD_2x64& D0,
                                 SIMD_2x64& D1) {
   A0 += B0 + SIMD_2x64::mul2_32(A0, B0);
   A1 += B1 + SIMD_2x64::mul2_32(A1, B1);
   D0 ^= A0;
   D1 ^= A1;
   D0 = D0.rotr<32>();
   D1 = D1.rotr<32>();

   C0 += D0 + SIMD_2x64::mul2_32(C0, D0);
   C1 += D1 + SIMD_2x64::mul2_32(C1, D1);
   B0 ^= C0;
   B1 ^= C1;
   B0 = B0.rotr<24>();
   B1 = B1.rotr<24>();

   A0 += B0 + SIMD_2x64::mul2_32(A0, B0);
   A1 += B1 + SIMD_2x64::mul2_32(A1, B1);
   D0 ^= A0;
   D1 ^= A1;
   D0 = D0.rotr<16>();
   D1 = D1.rotr<16>();

   C0 += D0 + SIMD_2x64::mul2_32(C0, D0);
   C1 += D1 + SIMD_2x64::mul2_32(C1, D1);
   B0 ^= C0;
   B1 ^= C1;
   B0 = B0.rotr<63>();
   B1 = B1.rotr<63>();
}

BOTAN_FORCE_INLINE void blamka_R(SIMD_2x64& A0,
                                 SIMD_2x64& A1,
                                 SIMD_2x64& B0,
                                 SIMD_2x64& B1,
                                 SIMD_2x64& C0,
                                 SIMD_2x64& C1,
                                 SIMD_2x64& D0,
                                 SIMD_2x64& D1) {
   blamka_G(A0, A1, B0, B1, C0, C1, D0, D1);

   SIMD_2x64::twist(B0, B1, C0, C1, D0, D1);
   blamka_G(A0, A1, B0, B1, C0, C1, D0, D1);
   SIMD_2x64::untwist(B0, B1, C0, C1, D0, D1);
}

}  // namespace

void Argon2::blamka_ssse3(uint64_t N[128], uint64_t T[128]) {
   for(size_t i = 0; i != 8; ++i) {
      SIMD_2x64 Tv[8];
      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j] = SIMD_2x64::load_le(&N[16 * i + 4 * j]);
         Tv[2 * j + 1] = SIMD_2x64::load_le(&N[16 * i + 4 * j + 2]);
      }

      blamka_R(Tv[0], Tv[1], Tv[2], Tv[3], Tv[4], Tv[5], Tv[6], Tv[7]);

      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j].store_le(&T[16 * i + 4 * j]);
         Tv[2 * j + 1].store_le(&T[16 * i + 4 * j + 2]);
      }
   }

   for(size_t i = 0; i != 8; ++i) {
      SIMD_2x64 Tv[8];
      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j] = SIMD_2x64::load_le(&T[2 * i + 32 * j]);
         Tv[2 * j + 1] = SIMD_2x64::load_le(&T[2 * i + 32 * j + 16]);
      }

      blamka_R(Tv[0], Tv[1], Tv[2], Tv[3], Tv[4], Tv[5], Tv[6], Tv[7]);

      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j].store_le(&T[2 * i + 32 * j]);
         Tv[2 * j + 1].store_le(&T[2 * i + 32 * j + 16]);
      }
   }

   for(size_t i = 0; i != 128 / 4; ++i) {
      SIMD_2x64 n0 = SIMD_2x64::load_le(&N[4 * i]);
      SIMD_2x64 n1 = SIMD_2x64::load_le(&N[4 * i + 2]);

      n0 ^= SIMD_2x64::load_le(&T[4 * i]);
      n1 ^= SIMD_2x64::load_le(&T[4 * i + 2]);
      n0.store_le(&N[4 * i]);
      n1.store_le(&N[4 * i + 2]);
   }
}

}  // namespace Botan
