/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/twofish.h>

#include <botan/mem_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_avx512.h>
#include <immintrin.h>

namespace Botan {

namespace {

namespace Twofish_AVX512 {

// NOLINTBEGIN(portability-simd-intrinsics)

template <size_t N>
BOTAN_FN_ISA_AVX512_GFNI BOTAN_FORCE_INLINE __m512i lookup_sbox(const SIMD_16x32 W, const uint8_t* QS) {
   static_assert(N < 4);

   // Parallel sbox lookup using permutations + blend

   const auto q0 = _mm512_loadu_si512(QS);
   const auto q1 = _mm512_loadu_si512(QS + 64);
   const auto q2 = _mm512_loadu_si512(QS + 128);
   const auto q3 = _mm512_loadu_si512(QS + 192);

   const auto bytemask = _mm512_set1_epi32(0xFF);
   const auto idx = _mm512_and_si512(_mm512_srli_epi32(W.raw(), N * 8), bytemask);

   // Select on both Q[0-128] and Q[128-256] using the low 7 bits
   const __m512i lo = _mm512_permutex2var_epi8(q0, idx, q1);
   const __m512i hi = _mm512_permutex2var_epi8(q2, idx, q3);

   // Then select between those results using the top bit
   return _mm512_mask_blend_epi8(_mm512_movepi8_mask(idx), lo, hi);
}

BOTAN_FN_ISA_AVX512_GFNI
BOTAN_FORCE_INLINE SIMD_16x32 apply_mds(__m512i q, __m512i mds_gfni) {
   // clang-format off
   alignas(64) constexpr uint8_t MDS_PRE_SHUFFLE[64] = {
      0,  4,  8, 12, 16, 20, 24, 28,  0,  4,  8, 12, 16, 20, 24, 28,
      0,  4,  8, 12, 16, 20, 24, 28,  0,  4,  8, 12, 16, 20, 24, 28,
      32, 36, 40, 44, 48, 52, 56, 60, 32, 36, 40, 44, 48, 52, 56, 60,
      32, 36, 40, 44, 48, 52, 56, 60, 32, 36, 40, 44, 48, 52, 56, 60,
   };

   alignas(64) constexpr uint8_t MDS_POST_SHUFFLE[64] = {
      0,  8, 16, 24,  1,  9, 17, 25,  2, 10, 18, 26,  3, 11, 19, 27,
      4, 12, 20, 28,  5, 13, 21, 29,  6, 14, 22, 30,  7, 15, 23, 31,
      32, 40, 48, 56, 33, 41, 49, 57, 34, 42, 50, 58, 35, 43, 51, 59,
      36, 44, 52, 60, 37, 45, 53, 61, 38, 46, 54, 62, 39, 47, 55, 63,
   };
   // clang-format on

   const __m512i pre = _mm512_permutexvar_epi8(_mm512_load_si512(MDS_PRE_SHUFFLE), q);
   const __m512i transformed = _mm512_gf2p8affine_epi64_epi8(pre, mds_gfni, 0);
   return SIMD_16x32(_mm512_permutexvar_epi8(_mm512_load_si512(MDS_POST_SHUFFLE), transformed));
}

BOTAN_FN_ISA_AVX512_GFNI
BOTAN_FORCE_INLINE SIMD_16x32 g_func(SIMD_16x32 W, const uint8_t* QS) {
   constexpr uint64_t GFNI_ID = 0x0102040810204080;
   constexpr uint64_t GFNI_5B = 0x050B162953A24182;
   constexpr uint64_t GFNI_EF = 0x070F1F3972E3C183;

   const __m512i MDS0 = _mm512_set_epi64(GFNI_EF, GFNI_EF, GFNI_5B, GFNI_ID, GFNI_EF, GFNI_EF, GFNI_5B, GFNI_ID);
   const __m512i MDS1 = _mm512_set_epi64(GFNI_ID, GFNI_5B, GFNI_EF, GFNI_EF, GFNI_ID, GFNI_5B, GFNI_EF, GFNI_EF);
   const __m512i MDS2 = _mm512_set_epi64(GFNI_EF, GFNI_ID, GFNI_EF, GFNI_5B, GFNI_EF, GFNI_ID, GFNI_EF, GFNI_5B);
   const __m512i MDS3 = _mm512_set_epi64(GFNI_5B, GFNI_EF, GFNI_ID, GFNI_5B, GFNI_5B, GFNI_EF, GFNI_ID, GFNI_5B);

   const auto r0 = apply_mds(lookup_sbox<0>(W, QS), MDS0);
   const auto r1 = apply_mds(lookup_sbox<1>(W, QS + 256), MDS1);
   const auto r2 = apply_mds(lookup_sbox<2>(W, QS + 512), MDS2);
   const auto r3 = apply_mds(lookup_sbox<3>(W, QS + 768), MDS3);

   return (r0 ^ r1 ^ r2 ^ r3);
}

// NOLINTEND(portability-simd-intrinsics)

BOTAN_FN_ISA_AVX512_GFNI
BOTAN_FORCE_INLINE void twofish_encrypt_round(
   SIMD_16x32 A, SIMD_16x32 B, SIMD_16x32& C, SIMD_16x32& D, uint32_t rk1, uint32_t rk2, const uint8_t* QS) {
   SIMD_16x32 X = g_func(A, QS);
   SIMD_16x32 Y = g_func(B.rotl<8>(), QS);

   X += Y;
   Y += X;

   X += SIMD_16x32::splat(rk1);
   Y += SIMD_16x32::splat(rk2);

   C = (C ^ X).rotr<1>();
   D = D.rotl<1>() ^ Y;
}

BOTAN_FN_ISA_AVX512_GFNI
BOTAN_FORCE_INLINE void twofish_decrypt_round(
   SIMD_16x32 A, SIMD_16x32 B, SIMD_16x32& C, SIMD_16x32& D, uint32_t rk1, uint32_t rk2, const uint8_t* QS) {
   SIMD_16x32 X = g_func(A, QS);
   SIMD_16x32 Y = g_func(B.rotl<8>(), QS);

   X += Y;
   Y += X;

   X += SIMD_16x32::splat(rk1);
   Y += SIMD_16x32::splat(rk2);

   C = C.rotl<1>() ^ X;
   D = (D ^ Y).rotr<1>();
}

BOTAN_FN_ISA_AVX512_GFNI
void encrypt_16(const uint8_t in[16 * 16], uint8_t out[16 * 16], std::span<const uint32_t> RK, const uint8_t* QS) {
   SIMD_16x32 B0 = SIMD_16x32::load_le(in);
   SIMD_16x32 B1 = SIMD_16x32::load_le(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_le(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_le(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   B0 ^= SIMD_16x32::splat(RK[0]);
   B1 ^= SIMD_16x32::splat(RK[1]);
   B2 ^= SIMD_16x32::splat(RK[2]);
   B3 ^= SIMD_16x32::splat(RK[3]);

   for(size_t k = 8; k != 40; k += 4) {
      twofish_encrypt_round(B0, B1, B2, B3, RK[k], RK[k + 1], QS);
      twofish_encrypt_round(B2, B3, B0, B1, RK[k + 2], RK[k + 3], QS);
   }

   B2 ^= SIMD_16x32::splat(RK[4]);
   B3 ^= SIMD_16x32::splat(RK[5]);
   B0 ^= SIMD_16x32::splat(RK[6]);
   B1 ^= SIMD_16x32::splat(RK[7]);

   SIMD_16x32::transpose(B2, B3, B0, B1);

   B2.store_le(out);
   B3.store_le(out + 64);
   B0.store_le(out + 128);
   B1.store_le(out + 192);
}

BOTAN_FN_ISA_AVX512_GFNI
void decrypt_16(const uint8_t in[16 * 16], uint8_t out[16 * 16], std::span<const uint32_t> RK, const uint8_t* QS) {
   SIMD_16x32 B0 = SIMD_16x32::load_le(in);
   SIMD_16x32 B1 = SIMD_16x32::load_le(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_le(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_le(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   B0 ^= SIMD_16x32::splat(RK[4]);
   B1 ^= SIMD_16x32::splat(RK[5]);
   B2 ^= SIMD_16x32::splat(RK[6]);
   B3 ^= SIMD_16x32::splat(RK[7]);

   for(size_t k = 40; k != 8; k -= 4) {
      twofish_decrypt_round(B0, B1, B2, B3, RK[k - 2], RK[k - 1], QS);
      twofish_decrypt_round(B2, B3, B0, B1, RK[k - 4], RK[k - 3], QS);
   }

   B2 ^= SIMD_16x32::splat(RK[0]);
   B3 ^= SIMD_16x32::splat(RK[1]);
   B0 ^= SIMD_16x32::splat(RK[2]);
   B1 ^= SIMD_16x32::splat(RK[3]);

   SIMD_16x32::transpose(B2, B3, B0, B1);

   B2.store_le(out);
   B3.store_le(out + 64);
   B0.store_le(out + 128);
   B1.store_le(out + 192);
}

}  // namespace Twofish_AVX512

}  // namespace

void BOTAN_FN_ISA_AVX512_GFNI Twofish::avx512_encrypt(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace Twofish_AVX512;

   const uint8_t* QS = m_QS.data();

   while(blocks >= 16) {
      encrypt_16(in, out, m_RK, QS);
      in += 16 * BLOCK_SIZE;
      out += 16 * BLOCK_SIZE;
      blocks -= 16;
   }

   if(blocks > 0) {
      uint8_t ibuf[16 * BLOCK_SIZE] = {0};
      uint8_t obuf[16 * BLOCK_SIZE] = {0};
      copy_mem(ibuf, in, blocks * BLOCK_SIZE);
      encrypt_16(ibuf, obuf, m_RK, QS);
      copy_mem(out, obuf, blocks * BLOCK_SIZE);
   }

   SIMD_16x32::zero_registers();
}

void BOTAN_FN_ISA_AVX512_GFNI Twofish::avx512_decrypt(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace Twofish_AVX512;

   const uint8_t* QS = m_QS.data();

   while(blocks >= 16) {
      decrypt_16(in, out, m_RK, QS);
      in += 16 * BLOCK_SIZE;
      out += 16 * BLOCK_SIZE;
      blocks -= 16;
   }

   if(blocks > 0) {
      uint8_t ibuf[16 * BLOCK_SIZE] = {0};
      uint8_t obuf[16 * BLOCK_SIZE] = {0};
      copy_mem(ibuf, in, blocks * BLOCK_SIZE);
      decrypt_16(ibuf, obuf, m_RK, QS);
      copy_mem(out, obuf, blocks * BLOCK_SIZE);
   }

   SIMD_16x32::zero_registers();
}

}  // namespace Botan
