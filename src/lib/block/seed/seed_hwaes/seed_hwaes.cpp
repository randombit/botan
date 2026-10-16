/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/seed.h>

#include <botan/mem_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/simd_hwaes.h>

namespace Botan {

namespace SEED_HWAES {

namespace {

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 seed_g(SIMD_4x32 X) {
   // Field isomorphism from SEED's field (0x163) to AES field (0x11B)
   constexpr uint64_t pre_a = gfni_matrix(R"(
      1 1 0 1 0 0 0 0
      0 0 1 1 0 0 1 1
      0 0 0 0 1 1 0 1
      0 1 1 1 0 1 0 0
      0 1 1 0 1 0 0 0
      0 0 0 1 1 0 0 0
      0 0 1 1 1 1 0 0
      0 0 0 0 1 1 1 0)");

   // AES->SEED field isomorphism composed with S0's affine
   constexpr uint64_t s0_post_a = gfni_matrix(R"(
      0 1 0 1 1 0 0 1
      0 0 1 1 1 0 1 0
      1 0 0 0 1 1 1 0
      1 1 0 0 1 0 0 1
      0 1 0 1 1 0 1 1
      1 1 1 1 1 0 1 1
      0 0 1 1 0 1 0 1
      0 0 0 1 0 1 1 1)");
   constexpr uint8_t s0_post_c = 0xA9;

   // AES->SEED field isomorphism composed with S1's affine
   constexpr uint64_t s1_post_a = gfni_matrix(R"(
      0 0 1 1 0 1 1 0
      0 1 1 0 0 0 1 0
      0 1 0 1 1 0 1 1
      0 0 0 0 0 0 1 1
      1 1 0 1 0 0 0 0
      0 1 0 0 1 0 1 1
      1 1 1 0 1 0 1 1
      1 1 1 1 0 0 0 1)");
   constexpr uint8_t s1_post_c = 0x38;

   constexpr auto pre = Gf2AffineTransformation(pre_a, 0x00);
   constexpr auto post_s0 = Gf2AffineTransformation::post_sbox(s0_post_a, s0_post_c);
   constexpr auto post_s1 = Gf2AffineTransformation::post_sbox(s1_post_a, s1_post_c);

   // Shared computation for S0(x) and S1(x)
   const auto sub = hw_aes_sbox(pre.affine_transform(X));

   // Compute S0(x) and S1(x)
   const auto s0 = post_s0.affine_transform(sub);
   const auto s1 = post_s1.affine_transform(sub);

   // Blend S0(x) and S1(x) outputs in alternating bytes
   const auto sbox = SIMD_4x32::byte_blend(0x00FF00FF, s0, s1);

   // Linear mixing step
   const auto M0 = SIMD_4x32::splat(0x3FCFF3FC);
   const auto M1 = SIMD_4x32::splat(0xFC3FCFF3);
   const auto M2 = SIMD_4x32::splat(0xF3FC3FCF);
   const auto M3 = SIMD_4x32::splat(0xCFF3FC3F);

   // Broadcast each byte of a 32-bit word to all 4 positions
   const auto SHUF0 = SIMD_4x32(0x00000000, 0x04040404, 0x08080808, 0x0C0C0C0C);
   const auto SHUF1 = SIMD_4x32(0x01010101, 0x05050505, 0x09090909, 0x0D0D0D0D);
   const auto SHUF2 = SIMD_4x32(0x02020202, 0x06060606, 0x0A0A0A0A, 0x0E0E0E0E);
   const auto SHUF3 = SIMD_4x32(0x03030303, 0x07070707, 0x0B0B0B0B, 0x0F0F0F0F);

   const auto b0 = SIMD_4x32::byte_shuffle(sbox, SHUF0);
   const auto b1 = SIMD_4x32::byte_shuffle(sbox, SHUF1);
   const auto b2 = SIMD_4x32::byte_shuffle(sbox, SHUF2);
   const auto b3 = SIMD_4x32::byte_shuffle(sbox, SHUF3);

   return (b0 & M0) ^ (b1 & M1) ^ (b2 & M2) ^ (b3 & M3);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void seed_round(
   SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3, uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3) {
   auto T0 = B2 ^ SIMD_4x32::splat(K0);
   auto T1 = seed_g(B2 ^ B3 ^ SIMD_4x32::splat(K1));
   T0 = seed_g(T1 + T0);
   T1 = seed_g(T1 + T0);
   B1 ^= T1;
   B0 ^= T0 + T1;

   T0 = B0 ^ SIMD_4x32::splat(K2);
   T1 = seed_g(B0 ^ B1 ^ SIMD_4x32::splat(K3));
   T0 = seed_g(T1 + T0);
   T1 = seed_g(T1 + T0);
   B3 ^= T1;
   B2 ^= T0 + T1;
}

BOTAN_FN_ISA_HWAES void encrypt_4(const uint8_t ptext[4 * 16], uint8_t ctext[4 * 16], std::span<const uint32_t> RK) {
   auto B0 = SIMD_4x32::load_be(ptext);
   auto B1 = SIMD_4x32::load_be(ptext + 16);
   auto B2 = SIMD_4x32::load_be(ptext + 32);
   auto B3 = SIMD_4x32::load_be(ptext + 48);

   SIMD_4x32::transpose(B0, B1, B2, B3);

   for(size_t j = 0; j != 8; ++j) {
      const uint32_t K0 = RK[4 * j];
      const uint32_t K1 = RK[4 * j + 1];
      const uint32_t K2 = RK[4 * j + 2];
      const uint32_t K3 = RK[4 * j + 3];

      seed_round(B0, B1, B2, B3, K0, K1, K2, K3);
   }

   // Output order: B2, B3, B0, B1
   SIMD_4x32::transpose(B2, B3, B0, B1);

   B2.store_be(ctext);
   B3.store_be(ctext + 16);
   B0.store_be(ctext + 32);
   B1.store_be(ctext + 48);
}

BOTAN_FN_ISA_HWAES void decrypt_4(const uint8_t ctext[4 * 16], uint8_t ptext[4 * 16], std::span<const uint32_t> RK) {
   auto B0 = SIMD_4x32::load_be(ctext);
   auto B1 = SIMD_4x32::load_be(ctext + 16);
   auto B2 = SIMD_4x32::load_be(ctext + 32);
   auto B3 = SIMD_4x32::load_be(ctext + 48);

   SIMD_4x32::transpose(B0, B1, B2, B3);

   for(size_t j = 0; j != 8; ++j) {
      const uint32_t K0 = RK[30 - 4 * j];
      const uint32_t K1 = RK[31 - 4 * j];
      const uint32_t K2 = RK[28 - 4 * j];
      const uint32_t K3 = RK[29 - 4 * j];

      seed_round(B0, B1, B2, B3, K0, K1, K2, K3);
   }

   SIMD_4x32::transpose(B2, B3, B0, B1);

   B2.store_be(ptext);
   B3.store_be(ptext + 16);
   B0.store_be(ptext + 32);
   B1.store_be(ptext + 48);
}

}  // namespace

}  // namespace SEED_HWAES

void BOTAN_FN_ISA_HWAES SEED::hwaes_encrypt(const uint8_t ptext[], uint8_t ctext[], size_t blocks) const {
   while(blocks >= 4) {
      SEED_HWAES::encrypt_4(ptext, ctext, m_K);
      ptext += 4 * 16;
      ctext += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t pbuf[4 * 16] = {0};
      uint8_t cbuf[4 * 16] = {0};
      copy_mem(pbuf, ptext, blocks * 16);
      SEED_HWAES::encrypt_4(pbuf, cbuf, m_K);
      copy_mem(ctext, cbuf, blocks * 16);
   }
}

void BOTAN_FN_ISA_HWAES SEED::hwaes_decrypt(const uint8_t ctext[], uint8_t ptext[], size_t blocks) const {
   while(blocks >= 4) {
      SEED_HWAES::decrypt_4(ctext, ptext, m_K);
      ptext += 4 * 16;
      ctext += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t cbuf[4 * 16] = {0};
      uint8_t pbuf[4 * 16] = {0};
      copy_mem(cbuf, ctext, blocks * 16);
      SEED_HWAES::decrypt_4(cbuf, pbuf, m_K);
      copy_mem(ptext, pbuf, blocks * 16);
   }
}

}  // namespace Botan
