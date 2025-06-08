/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/shacal2.h>

#include <botan/internal/simd_avx2.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

namespace SHACAL2_AVX512_F {

namespace {

/*
* 8x16 Transpose
*
* Convert from
*
* A00 B00 C00 ... H00
* A01 B01 C01 ... H01
* ..
* A15 B15 C15 ... H15
*
* with two blocks stored in each register, into
*
* A00 A01 ... A15
* B00 B01 ... B15
* ...
* H00 H01 ... H15
*/
BOTAN_FN_ISA_AVX512
void transpose_in(SIMD_16x32& B0,
                  SIMD_16x32& B1,
                  SIMD_16x32& B2,
                  SIMD_16x32& B3,
                  SIMD_16x32& B4,
                  SIMD_16x32& B5,
                  SIMD_16x32& B6,
                  SIMD_16x32& B7) {
   auto t0 = _mm512_unpacklo_epi32(B0.raw(), B1.raw());
   auto t1 = _mm512_unpackhi_epi32(B0.raw(), B1.raw());
   auto t2 = _mm512_unpacklo_epi32(B2.raw(), B3.raw());
   auto t3 = _mm512_unpackhi_epi32(B2.raw(), B3.raw());
   auto t4 = _mm512_unpacklo_epi32(B4.raw(), B5.raw());
   auto t5 = _mm512_unpackhi_epi32(B4.raw(), B5.raw());
   auto t6 = _mm512_unpacklo_epi32(B6.raw(), B7.raw());
   auto t7 = _mm512_unpackhi_epi32(B6.raw(), B7.raw());

   auto r0 = _mm512_unpacklo_epi64(t0, t2);
   auto r1 = _mm512_unpackhi_epi64(t0, t2);
   auto r2 = _mm512_unpacklo_epi64(t1, t3);
   auto r3 = _mm512_unpackhi_epi64(t1, t3);
   auto r4 = _mm512_unpacklo_epi64(t4, t6);
   auto r5 = _mm512_unpackhi_epi64(t4, t6);
   auto r6 = _mm512_unpacklo_epi64(t5, t7);
   auto r7 = _mm512_unpackhi_epi64(t5, t7);

   const __m512i tbl0 = _mm512_set_epi32(27, 19, 26, 18, 25, 17, 24, 16, 11, 3, 10, 2, 9, 1, 8, 0);
   const __m512i tbl1 = _mm512_add_epi32(tbl0, _mm512_set1_epi32(4));
   B0 = SIMD_16x32(_mm512_permutex2var_epi32(r0, tbl0, r4));
   B1 = SIMD_16x32(_mm512_permutex2var_epi32(r1, tbl0, r5));
   B2 = SIMD_16x32(_mm512_permutex2var_epi32(r2, tbl0, r6));
   B3 = SIMD_16x32(_mm512_permutex2var_epi32(r3, tbl0, r7));
   B4 = SIMD_16x32(_mm512_permutex2var_epi32(r0, tbl1, r4));
   B5 = SIMD_16x32(_mm512_permutex2var_epi32(r1, tbl1, r5));
   B6 = SIMD_16x32(_mm512_permutex2var_epi32(r2, tbl1, r6));
   B7 = SIMD_16x32(_mm512_permutex2var_epi32(r3, tbl1, r7));
}

BOTAN_FN_ISA_AVX512
void transpose_out(SIMD_16x32& B0,
                   SIMD_16x32& B1,
                   SIMD_16x32& B2,
                   SIMD_16x32& B3,
                   SIMD_16x32& B4,
                   SIMD_16x32& B5,
                   SIMD_16x32& B6,
                   SIMD_16x32& B7) {
   auto t0 = _mm512_unpacklo_epi32(B0.raw(), B1.raw());
   auto t1 = _mm512_unpackhi_epi32(B0.raw(), B1.raw());
   auto t2 = _mm512_unpacklo_epi32(B2.raw(), B3.raw());
   auto t3 = _mm512_unpackhi_epi32(B2.raw(), B3.raw());
   auto t4 = _mm512_unpacklo_epi32(B4.raw(), B5.raw());
   auto t5 = _mm512_unpackhi_epi32(B4.raw(), B5.raw());
   auto t6 = _mm512_unpacklo_epi32(B6.raw(), B7.raw());
   auto t7 = _mm512_unpackhi_epi32(B6.raw(), B7.raw());

   auto r0 = _mm512_unpacklo_epi64(t0, t2);
   auto r1 = _mm512_unpackhi_epi64(t0, t2);
   auto r2 = _mm512_unpacklo_epi64(t1, t3);
   auto r3 = _mm512_unpackhi_epi64(t1, t3);
   auto r4 = _mm512_unpacklo_epi64(t4, t6);
   auto r5 = _mm512_unpackhi_epi64(t4, t6);
   auto r6 = _mm512_unpacklo_epi64(t5, t7);
   auto r7 = _mm512_unpackhi_epi64(t5, t7);

   const __m512i tbl0 = _mm512_set_epi32(23, 22, 21, 20, 7, 6, 5, 4, 19, 18, 17, 16, 3, 2, 1, 0);
   const __m512i tbl1 = _mm512_add_epi32(tbl0, _mm512_set1_epi32(8));

   auto s0 = _mm512_permutex2var_epi32(r0, tbl0, r4);
   auto s1 = _mm512_permutex2var_epi32(r1, tbl0, r5);
   auto s2 = _mm512_permutex2var_epi32(r2, tbl0, r6);
   auto s3 = _mm512_permutex2var_epi32(r3, tbl0, r7);
   auto s4 = _mm512_permutex2var_epi32(r0, tbl1, r4);
   auto s5 = _mm512_permutex2var_epi32(r1, tbl1, r5);
   auto s6 = _mm512_permutex2var_epi32(r2, tbl1, r6);
   auto s7 = _mm512_permutex2var_epi32(r3, tbl1, r7);

   B0 = SIMD_16x32(_mm512_shuffle_i32x4(s0, s1, 0b01000100));
   B1 = SIMD_16x32(_mm512_shuffle_i32x4(s2, s3, 0b01000100));
   B2 = SIMD_16x32(_mm512_shuffle_i32x4(s0, s1, 0b11101110));
   B3 = SIMD_16x32(_mm512_shuffle_i32x4(s2, s3, 0b11101110));
   B4 = SIMD_16x32(_mm512_shuffle_i32x4(s4, s5, 0b01000100));
   B5 = SIMD_16x32(_mm512_shuffle_i32x4(s6, s7, 0b01000100));
   B6 = SIMD_16x32(_mm512_shuffle_i32x4(s4, s5, 0b11101110));
   B7 = SIMD_16x32(_mm512_shuffle_i32x4(s6, s7, 0b11101110));
}

template <typename SimdT>
void BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 SHACAL2_Fwd(const SimdT& A,
                                                        const SimdT& B,
                                                        const SimdT& C,
                                                        SimdT& D,
                                                        const SimdT& E,
                                                        const SimdT& F,
                                                        const SimdT& G,
                                                        SimdT& H,
                                                        uint32_t RK) {
   H += E.sigma1() + SimdT::choose(E, F, G) + SimdT::splat(RK);
   D += H;
   H += A.sigma0() + SimdT::majority(A, B, C);
}

template <typename SimdT>
void BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 SHACAL2_Rev(const SimdT& A,
                                                        const SimdT& B,
                                                        const SimdT& C,
                                                        SimdT& D,
                                                        const SimdT& E,
                                                        const SimdT& F,
                                                        const SimdT& G,
                                                        SimdT& H,
                                                        uint32_t RK) {
   H -= A.sigma0() + SimdT::majority(A, B, C);
   D -= H;
   H -= E.sigma1() + SimdT::choose(E, F, G) + SimdT::splat(RK);
}

}  // namespace

}  // namespace SHACAL2_AVX512_F

size_t BOTAN_FN_ISA_AVX512 SHACAL2::avx512_encrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace SHACAL2_AVX512_F;

   size_t consumed = 0;

   while(blocks >= 16) {
      SIMD_16x32 A = SIMD_16x32::load_be(in + 64 * 0);
      SIMD_16x32 B = SIMD_16x32::load_be(in + 64 * 1);
      SIMD_16x32 C = SIMD_16x32::load_be(in + 64 * 2);
      SIMD_16x32 D = SIMD_16x32::load_be(in + 64 * 3);
      SIMD_16x32 E = SIMD_16x32::load_be(in + 64 * 4);
      SIMD_16x32 F = SIMD_16x32::load_be(in + 64 * 5);
      SIMD_16x32 G = SIMD_16x32::load_be(in + 64 * 6);
      SIMD_16x32 H = SIMD_16x32::load_be(in + 64 * 7);

      transpose_in(A, B, C, D, E, F, G, H);

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

      transpose_out(A, B, C, D, E, F, G, H);

      A.store_be(out + 64 * 0);
      B.store_be(out + 64 * 1);
      C.store_be(out + 64 * 2);
      D.store_be(out + 64 * 3);
      E.store_be(out + 64 * 4);
      F.store_be(out + 64 * 5);
      G.store_be(out + 64 * 6);
      H.store_be(out + 64 * 7);

      in += 16 * BLOCK_SIZE;
      out += 16 * BLOCK_SIZE;
      blocks -= 16;
      consumed += 16;
   }

   while(blocks >= 8) {
      SIMD_8x32 A = SIMD_8x32::load_be(in + 32 * 0);
      SIMD_8x32 B = SIMD_8x32::load_be(in + 32 * 1);
      SIMD_8x32 C = SIMD_8x32::load_be(in + 32 * 2);
      SIMD_8x32 D = SIMD_8x32::load_be(in + 32 * 3);
      SIMD_8x32 E = SIMD_8x32::load_be(in + 32 * 4);
      SIMD_8x32 F = SIMD_8x32::load_be(in + 32 * 5);
      SIMD_8x32 G = SIMD_8x32::load_be(in + 32 * 6);
      SIMD_8x32 H = SIMD_8x32::load_be(in + 32 * 7);

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

      A.store_be(out + 32 * 0);
      B.store_be(out + 32 * 1);
      C.store_be(out + 32 * 2);
      D.store_be(out + 32 * 3);
      E.store_be(out + 32 * 4);
      F.store_be(out + 32 * 5);
      G.store_be(out + 32 * 6);
      H.store_be(out + 32 * 7);

      in += 8 * BLOCK_SIZE;
      out += 8 * BLOCK_SIZE;
      blocks -= 8;
      consumed += 8;
   }

   return consumed;
}

size_t BOTAN_FN_ISA_AVX512 SHACAL2::avx512_decrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace SHACAL2_AVX512_F;

   size_t consumed = 0;

   while(blocks >= 16) {
      SIMD_16x32 A = SIMD_16x32::load_be(in + 64 * 0);
      SIMD_16x32 B = SIMD_16x32::load_be(in + 64 * 1);
      SIMD_16x32 C = SIMD_16x32::load_be(in + 64 * 2);
      SIMD_16x32 D = SIMD_16x32::load_be(in + 64 * 3);
      SIMD_16x32 E = SIMD_16x32::load_be(in + 64 * 4);
      SIMD_16x32 F = SIMD_16x32::load_be(in + 64 * 5);
      SIMD_16x32 G = SIMD_16x32::load_be(in + 64 * 6);
      SIMD_16x32 H = SIMD_16x32::load_be(in + 64 * 7);

      transpose_in(A, B, C, D, E, F, G, H);

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

      transpose_out(A, B, C, D, E, F, G, H);

      A.store_be(out + 64 * 0);
      B.store_be(out + 64 * 1);
      C.store_be(out + 64 * 2);
      D.store_be(out + 64 * 3);
      E.store_be(out + 64 * 4);
      F.store_be(out + 64 * 5);
      G.store_be(out + 64 * 6);
      H.store_be(out + 64 * 7);

      in += 16 * BLOCK_SIZE;
      out += 16 * BLOCK_SIZE;
      blocks -= 16;
      consumed += 16;
   }

   while(blocks >= 8) {
      SIMD_8x32 A = SIMD_8x32::load_be(in + 32 * 0);
      SIMD_8x32 B = SIMD_8x32::load_be(in + 32 * 1);
      SIMD_8x32 C = SIMD_8x32::load_be(in + 32 * 2);
      SIMD_8x32 D = SIMD_8x32::load_be(in + 32 * 3);
      SIMD_8x32 E = SIMD_8x32::load_be(in + 32 * 4);
      SIMD_8x32 F = SIMD_8x32::load_be(in + 32 * 5);
      SIMD_8x32 G = SIMD_8x32::load_be(in + 32 * 6);
      SIMD_8x32 H = SIMD_8x32::load_be(in + 32 * 7);

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

      A.store_be(out + 32 * 0);
      B.store_be(out + 32 * 1);
      C.store_be(out + 32 * 2);
      D.store_be(out + 32 * 3);
      E.store_be(out + 32 * 4);
      F.store_be(out + 32 * 5);
      G.store_be(out + 32 * 6);
      H.store_be(out + 32 * 7);

      in += 8 * BLOCK_SIZE;
      out += 8 * BLOCK_SIZE;
      blocks -= 8;
      consumed += 8;
   }

   return consumed;
}

}  // namespace Botan
