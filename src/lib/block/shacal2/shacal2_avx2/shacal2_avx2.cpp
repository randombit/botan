/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/shacal2.h>

#include <botan/internal/simd_avx2.h>

namespace Botan {

namespace {

void BOTAN_FORCE_INLINE BOTAN_AVX2_FN SHACAL2_Fwd(const SIMD_8x32& A,
                                                  const SIMD_8x32& B,
                                                  const SIMD_8x32& C,
                                                  SIMD_8x32& D,
                                                  const SIMD_8x32& E,
                                                  const SIMD_8x32& F,
                                                  const SIMD_8x32& G,
                                                  SIMD_8x32& H,
                                                  uint32_t RK) {
   H += E.sigma1() + SIMD_8x32::choose(E, F, G) + SIMD_8x32::splat(RK);
   D += H;
   H += A.sigma0() + SIMD_8x32::majority(A, B, C);
}

void BOTAN_FORCE_INLINE BOTAN_AVX2_FN SHACAL2_Rev(const SIMD_8x32& A,
                                                  const SIMD_8x32& B,
                                                  const SIMD_8x32& C,
                                                  SIMD_8x32& D,
                                                  const SIMD_8x32& E,
                                                  const SIMD_8x32& F,
                                                  const SIMD_8x32& G,
                                                  SIMD_8x32& H,
                                                  uint32_t RK) {
   H -= A.sigma0() + SIMD_8x32::majority(A, B, C);
   D -= H;
   H -= E.sigma1() + SIMD_8x32::choose(E, F, G) + SIMD_8x32::splat(RK);
}

}  // namespace

void BOTAN_AVX2_FN SHACAL2::avx2_encrypt_8(const uint8_t in[], uint8_t out[]) const {
   SIMD_8x32::reset_registers();

   SIMD_8x32 A = SIMD_8x32::load_be(in);
   SIMD_8x32 B = SIMD_8x32::load_be(in + 32);
   SIMD_8x32 C = SIMD_8x32::load_be(in + 64);
   SIMD_8x32 D = SIMD_8x32::load_be(in + 96);

   SIMD_8x32 E = SIMD_8x32::load_be(in + 128);
   SIMD_8x32 F = SIMD_8x32::load_be(in + 160);
   SIMD_8x32 G = SIMD_8x32::load_be(in + 192);
   SIMD_8x32 H = SIMD_8x32::load_be(in + 224);

   SIMD_8x32::transpose(A, B, C, D, E, F, G, H);

   for(size_t r = 0; r != 64; r += 8) {
      SHACAL2_Fwd(A, B, C, D, E, F, G, H, m_RK[r + 0]);
      SHACAL2_Fwd(H, A, B, C, D, E, F, G, m_RK[r + 1]);
      SHACAL2_Fwd(G, H, A, B, C, D, E, F, m_RK[r + 2]);
      SHACAL2_Fwd(F, G, H, A, B, C, D, E, m_RK[r + 3]);
      SHACAL2_Fwd(E, F, G, H, A, B, C, D, m_RK[r + 4]);
      SHACAL2_Fwd(D, E, F, G, H, A, B, C, m_RK[r + 5]);
      SHACAL2_Fwd(C, D, E, F, G, H, A, B, m_RK[r + 6]);
      SHACAL2_Fwd(B, C, D, E, F, G, H, A, m_RK[r + 7]);
   }

   SIMD_8x32::transpose(A, B, C, D, E, F, G, H);

   A.store_be(out);
   B.store_be(out + 32);
   C.store_be(out + 64);
   D.store_be(out + 96);

   E.store_be(out + 128);
   F.store_be(out + 160);
   G.store_be(out + 192);
   H.store_be(out + 224);

   SIMD_8x32::zero_registers();
}

BOTAN_AVX2_FN void SHACAL2::avx2_decrypt_8(const uint8_t in[], uint8_t out[]) const {
   SIMD_8x32::reset_registers();

   SIMD_8x32 A = SIMD_8x32::load_be(in);
   SIMD_8x32 B = SIMD_8x32::load_be(in + 32);
   SIMD_8x32 C = SIMD_8x32::load_be(in + 64);
   SIMD_8x32 D = SIMD_8x32::load_be(in + 96);

   SIMD_8x32 E = SIMD_8x32::load_be(in + 128);
   SIMD_8x32 F = SIMD_8x32::load_be(in + 160);
   SIMD_8x32 G = SIMD_8x32::load_be(in + 192);
   SIMD_8x32 H = SIMD_8x32::load_be(in + 224);

   SIMD_8x32::transpose(A, B, C, D, E, F, G, H);

   for(size_t r = 0; r != 64; r += 8) {
      SHACAL2_Rev(B, C, D, E, F, G, H, A, m_RK[63 - r]);
      SHACAL2_Rev(C, D, E, F, G, H, A, B, m_RK[62 - r]);
      SHACAL2_Rev(D, E, F, G, H, A, B, C, m_RK[61 - r]);
      SHACAL2_Rev(E, F, G, H, A, B, C, D, m_RK[60 - r]);
      SHACAL2_Rev(F, G, H, A, B, C, D, E, m_RK[59 - r]);
      SHACAL2_Rev(G, H, A, B, C, D, E, F, m_RK[58 - r]);
      SHACAL2_Rev(H, A, B, C, D, E, F, G, m_RK[57 - r]);
      SHACAL2_Rev(A, B, C, D, E, F, G, H, m_RK[56 - r]);
   }

   SIMD_8x32::transpose(A, B, C, D, E, F, G, H);

   A.store_be(out);
   B.store_be(out + 32);
   C.store_be(out + 64);
   D.store_be(out + 96);

   E.store_be(out + 128);
   F.store_be(out + 160);
   G.store_be(out + 192);
   H.store_be(out + 224);

   SIMD_8x32::zero_registers();
}

}  // namespace Botan
