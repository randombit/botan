/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm4.h>

#include <botan/internal/simd_avx2.h>
#include <botan/internal/simd_avx2_gfni.h>

namespace Botan {

namespace {

BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA) SIMD_8x32 sm4_sbox(const SIMD_8x32& x) {
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

BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA) SIMD_8x32 sm4_f(const SIMD_8x32& x) {
   SIMD_8x32 sx = sm4_sbox(x);
   return sx ^ sx.rotl<2>() ^ sx.rotl<10>() ^ sx.rotl<18>() ^ sx.rotl<24>();
}

BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA)
void sm4_gfni_encrypt_8(const uint8_t ptext[8 * 16], uint8_t ctext[8 * 16], std::span<const uint32_t> RK) {
   SIMD_8x32 B0 = SIMD_8x32::load_be(ptext);
   SIMD_8x32 B1 = SIMD_8x32::load_be(ptext + 16 * 2);
   SIMD_8x32 B2 = SIMD_8x32::load_be(ptext + 16 * 4);
   SIMD_8x32 B3 = SIMD_8x32::load_be(ptext + 16 * 6);

   SIMD_8x32::transpose(B0, B1, B2, B3);

   B0 = B0.rev_words();
   B1 = B1.rev_words();
   B2 = B2.rev_words();
   B3 = B3.rev_words();

   for(size_t j = 0; j != 8; ++j) {
      B0 ^= sm4_f(B1 ^ B2 ^ B3 ^ SIMD_8x32::splat(RK[4 * j]));
      B1 ^= sm4_f(B2 ^ B3 ^ B0 ^ SIMD_8x32::splat(RK[4 * j + 1]));
      B2 ^= sm4_f(B3 ^ B0 ^ B1 ^ SIMD_8x32::splat(RK[4 * j + 2]));
      B3 ^= sm4_f(B0 ^ B1 ^ B2 ^ SIMD_8x32::splat(RK[4 * j + 3]));
   }

   SIMD_8x32::transpose(B0, B1, B2, B3);

   B3.rev_words().store_be(ctext);
   B2.rev_words().store_be(ctext + 16 * 2);
   B1.rev_words().store_be(ctext + 16 * 4);
   B0.rev_words().store_be(ctext + 16 * 6);
}

BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA)
void sm4_gfni_decrypt_8(const uint8_t ctext[8 * 16], uint8_t ptext[8 * 16], std::span<const uint32_t> RK) {
   SIMD_8x32 B0 = SIMD_8x32::load_be(ctext);
   SIMD_8x32 B1 = SIMD_8x32::load_be(ctext + 16 * 2);
   SIMD_8x32 B2 = SIMD_8x32::load_be(ctext + 16 * 4);
   SIMD_8x32 B3 = SIMD_8x32::load_be(ctext + 16 * 6);

   SIMD_8x32::transpose(B0, B1, B2, B3);

   B0 = B0.rev_words();
   B1 = B1.rev_words();
   B2 = B2.rev_words();
   B3 = B3.rev_words();

   for(size_t j = 0; j != 8; ++j) {
      B0 ^= sm4_f(B1 ^ B2 ^ B3 ^ SIMD_8x32::splat(RK[32 - (4 * j + 1)]));
      B1 ^= sm4_f(B2 ^ B3 ^ B0 ^ SIMD_8x32::splat(RK[32 - (4 * j + 2)]));
      B2 ^= sm4_f(B3 ^ B0 ^ B1 ^ SIMD_8x32::splat(RK[32 - (4 * j + 3)]));
      B3 ^= sm4_f(B0 ^ B1 ^ B2 ^ SIMD_8x32::splat(RK[32 - (4 * j + 4)]));
   }

   SIMD_8x32::transpose(B0, B1, B2, B3);

   B3.rev_words().store_be(ptext);
   B2.rev_words().store_be(ptext + 16 * 2);
   B1.rev_words().store_be(ptext + 16 * 4);
   B0.rev_words().store_be(ptext + 16 * 6);
}

}  // namespace

void BOTAN_FUNC_ISA("gfni,avx2") SM4::sm4_gfni_encrypt(const uint8_t ptext[], uint8_t ctext[], size_t blocks) const {
   while(blocks >= 8) {
      sm4_gfni_encrypt_8(ptext, ctext, m_RK);
      ptext += 16 * 8;
      ctext += 16 * 8;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t pbuf[8 * 16] = {0};
      uint8_t cbuf[8 * 16] = {0};
      copy_mem(pbuf, ptext, blocks * 16);
      sm4_gfni_encrypt_8(pbuf, cbuf, m_RK);
      copy_mem(ctext, cbuf, blocks * 16);
   }
}

void BOTAN_FUNC_ISA("gfni,avx2") SM4::sm4_gfni_decrypt(const uint8_t ctext[], uint8_t ptext[], size_t blocks) const {
   while(blocks >= 8) {
      sm4_gfni_decrypt_8(ctext, ptext, m_RK);
      ptext += 16 * 8;
      ctext += 16 * 8;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t cbuf[8 * 16] = {0};
      uint8_t pbuf[8 * 16] = {0};
      copy_mem(cbuf, ctext, blocks * 16);
      sm4_gfni_decrypt_8(cbuf, pbuf, m_RK);
      copy_mem(ptext, pbuf, blocks * 16);
   }
}

}  // namespace Botan
