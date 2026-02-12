/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm4.h>

#include <botan/mem_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_avx2_gfni.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

namespace SM4_AVX512_GFNI {

namespace {

template <uint64_t A, uint8_t B>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_16x32 gf2p8affine(const SIMD_16x32& x) {
   return SIMD_16x32(_mm512_gf2p8affine_epi64_epi8(x.raw(), _mm512_set1_epi64(A), B));
}

template <uint64_t A, uint8_t B>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_16x32 gf2p8affineinv(const SIMD_16x32& x) {
   return SIMD_16x32(_mm512_gf2p8affineinv_epi64_epi8(x.raw(), _mm512_set1_epi64(A), B));
}

template <typename SIMD_T>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_T sm4_sbox(const SIMD_T& x) {
   /*
   * See https://eprint.iacr.org/2022/1154 section 3.3 for details on
   * how this works
   */
   constexpr uint64_t pre_a = gfni_matrix(R"(
      0 0 1 1 0 0 1 0
      0 0 0 1 0 1 0 0
      1 0 1 1 1 1 1 0
      1 0 0 1 1 1 0 1
      0 1 0 1 1 0 0 0
      0 1 0 0 0 1 0 0
      0 0 0 0 1 0 1 0
      1 0 1 1 1 0 1 0)");

   constexpr uint8_t pre_c = 0b00111110;

   constexpr uint64_t post_a = gfni_matrix(R"(
      1 1 0 0 1 1 1 1
      1 1 0 1 0 1 0 1
      0 0 1 0 1 1 0 0
      1 0 0 1 0 1 0 1
      0 0 1 0 1 1 1 0
      0 1 1 0 0 1 0 1
      1 0 1 0 1 1 0 1
      1 0 0 1 0 0 0 1)");

   constexpr uint8_t post_c = 0b11010011;

   auto y = gf2p8affine<pre_a, pre_c>(x);
   return gf2p8affineinv<post_a, post_c>(y);
}

template <typename SIMD_T>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_T sm4_f(const SIMD_T& x) {
   const auto sx = sm4_sbox(x);
   return sx ^ sx.template rotl<2>() ^ sx.template rotl<10>() ^ sx.template rotl<18>() ^ sx.template rotl<24>();
}

template <typename SIMD_T, size_t M>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void encrypt(const uint8_t ptext[16 * 4 * M],
                                                         uint8_t ctext[16 * 4 * M],
                                                         std::span<const uint32_t> RK) {
   SIMD_T B0 = SIMD_T::load_be(ptext);
   SIMD_T B1 = SIMD_T::load_be(ptext + 16 * M);
   SIMD_T B2 = SIMD_T::load_be(ptext + 16 * 2 * M);
   SIMD_T B3 = SIMD_T::load_be(ptext + 16 * 3 * M);

   SIMD_T::transpose(B0, B1, B2, B3);

   B0 = B0.rev_words();
   B1 = B1.rev_words();
   B2 = B2.rev_words();
   B3 = B3.rev_words();

   for(size_t j = 0; j != 8; ++j) {
      B0 ^= sm4_f(B1 ^ B2 ^ B3 ^ SIMD_T::splat(RK[4 * j]));
      B1 ^= sm4_f(B2 ^ B3 ^ B0 ^ SIMD_T::splat(RK[4 * j + 1]));
      B2 ^= sm4_f(B3 ^ B0 ^ B1 ^ SIMD_T::splat(RK[4 * j + 2]));
      B3 ^= sm4_f(B0 ^ B1 ^ B2 ^ SIMD_T::splat(RK[4 * j + 3]));
   }

   SIMD_T::transpose(B0, B1, B2, B3);

   B3.rev_words().store_be(ctext);
   B2.rev_words().store_be(ctext + 16 * M);
   B1.rev_words().store_be(ctext + 16 * 2 * M);
   B0.rev_words().store_be(ctext + 16 * 3 * M);
}

template <typename SIMD_T, size_t M>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void decrypt(const uint8_t ctext[16 * 4 * M],
                                                         uint8_t ptext[16 * 4 * M],
                                                         std::span<const uint32_t> RK) {
   SIMD_T B0 = SIMD_T::load_be(ctext);
   SIMD_T B1 = SIMD_T::load_be(ctext + 16 * M);
   SIMD_T B2 = SIMD_T::load_be(ctext + 16 * 2 * M);
   SIMD_T B3 = SIMD_T::load_be(ctext + 16 * 3 * M);

   SIMD_T::transpose(B0, B1, B2, B3);

   B0 = B0.rev_words();
   B1 = B1.rev_words();
   B2 = B2.rev_words();
   B3 = B3.rev_words();

   for(size_t j = 0; j != 8; ++j) {
      B0 ^= sm4_f(B1 ^ B2 ^ B3 ^ SIMD_T::splat(RK[32 - (4 * j + 1)]));
      B1 ^= sm4_f(B2 ^ B3 ^ B0 ^ SIMD_T::splat(RK[32 - (4 * j + 2)]));
      B2 ^= sm4_f(B3 ^ B0 ^ B1 ^ SIMD_T::splat(RK[32 - (4 * j + 3)]));
      B3 ^= sm4_f(B0 ^ B1 ^ B2 ^ SIMD_T::splat(RK[32 - (4 * j + 4)]));
   }

   SIMD_T::transpose(B0, B1, B2, B3);

   B3.rev_words().store_be(ptext);
   B2.rev_words().store_be(ptext + 16 * M);
   B1.rev_words().store_be(ptext + 16 * 2 * M);
   B0.rev_words().store_be(ptext + 16 * 3 * M);
}

}  // namespace

}  // namespace SM4_AVX512_GFNI

void BOTAN_FN_ISA_AVX512_GFNI SM4::sm4_avx512_gfni_encrypt(const uint8_t ptext[],
                                                           uint8_t ctext[],
                                                           size_t blocks) const {
   while(blocks >= 16) {
      SM4_AVX512_GFNI::encrypt<SIMD_16x32, 4>(ptext, ctext, m_RK);
      ptext += 16 * 16;
      ctext += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      SM4_AVX512_GFNI::encrypt<SIMD_8x32, 2>(ptext, ctext, m_RK);
      ptext += 16 * 8;
      ctext += 16 * 8;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t pbuf[16 * 8] = {0};
      uint8_t cbuf[16 * 8] = {0};
      copy_mem(pbuf, ptext, blocks * 16);
      SM4_AVX512_GFNI::encrypt<SIMD_8x32, 2>(pbuf, cbuf, m_RK);
      copy_mem(ctext, cbuf, blocks * 16);
   }
}

void BOTAN_FN_ISA_AVX512_GFNI SM4::sm4_avx512_gfni_decrypt(const uint8_t ctext[],
                                                           uint8_t ptext[],
                                                           size_t blocks) const {
   while(blocks >= 16) {
      SM4_AVX512_GFNI::decrypt<SIMD_16x32, 4>(ctext, ptext, m_RK);
      ptext += 16 * 16;
      ctext += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      SM4_AVX512_GFNI::decrypt<SIMD_8x32, 2>(ctext, ptext, m_RK);
      ptext += 16 * 8;
      ctext += 16 * 8;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t cbuf[16 * 8] = {0};
      uint8_t pbuf[16 * 8] = {0};
      copy_mem(cbuf, ctext, blocks * 16);
      SM4_AVX512_GFNI::decrypt<SIMD_8x32, 2>(cbuf, pbuf, m_RK);
      copy_mem(ptext, pbuf, blocks * 16);
   }
}

}  // namespace Botan
