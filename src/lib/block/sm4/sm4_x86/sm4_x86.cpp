/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm4.h>

#include <botan/mem_ops.h>
#include <botan/internal/simd_avx2.h>

namespace Botan {

namespace {

BOTAN_FUNC_ISA_INLINE("sm4,avx2") SIMD_8x32 sm4_x86_rnds4(const SIMD_8x32& b, const SIMD_8x32& k) {
   return SIMD_8x32(_mm256_sm4rnds4_epi32(b.raw(), k.raw()));
}

BOTAN_FUNC_ISA_INLINE("sm4,avx2")
void sm4_x86_encrypt_x2(uint8_t out[2 * 16], const uint8_t inp[2 * 16], std::span<const uint32_t> RK) {
   auto B0 = SIMD_8x32::load_be(inp);

   for(size_t i = 0; i != 8; ++i) {
      const auto RK_i = SIMD_8x32::load_le128(&RK[4 * i]);
      B0 = sm4_x86_rnds4(B0, RK_i);
   }

   B0.reverse().store_le(out);
}

BOTAN_FUNC_ISA_INLINE("sm4,avx2")
void sm4_x86_encrypt_x8(uint8_t out[8 * 16], const uint8_t inp[8 * 16], std::span<const uint32_t> RK) {
   auto B0 = SIMD_8x32::load_be(inp);
   auto B1 = SIMD_8x32::load_be(inp + 32);
   auto B2 = SIMD_8x32::load_be(inp + 64);
   auto B3 = SIMD_8x32::load_be(inp + 96);

   for(size_t i = 0; i != 8; ++i) {
      auto RK_i = SIMD_8x32::load_le128(&RK[4 * i]);
      B0 = sm4_x86_rnds4(B0, RK_i);
      B1 = sm4_x86_rnds4(B1, RK_i);
      B2 = sm4_x86_rnds4(B2, RK_i);
      B3 = sm4_x86_rnds4(B3, RK_i);
   }

   B0.reverse().store_le(out);
   B1.reverse().store_le(out + 32);
   B2.reverse().store_le(out + 64);
   B3.reverse().store_le(out + 96);
}

void sm4_x86_decrypt_x2(uint8_t out[2 * 16], const uint8_t inp[2 * 16], std::span<const uint32_t> RK) {
   auto B0 = SIMD_8x32::load_be(inp);

   for(size_t i = 0; i != 8; ++i) {
      auto RK_i = SIMD_8x32::load_le128(&RK[28 - 4 * i]).rev_words();
      B0 = sm4_x86_rnds4(B0, RK_i);
   }

   B0.reverse().store_le(out);
}

void sm4_x86_decrypt_x8(uint8_t out[8 * 16], const uint8_t inp[8 * 16], std::span<const uint32_t> RK) {
   auto B0 = SIMD_8x32::load_be(inp);
   auto B1 = SIMD_8x32::load_be(inp + 32);
   auto B2 = SIMD_8x32::load_be(inp + 64);
   auto B3 = SIMD_8x32::load_be(inp + 96);

   for(size_t i = 0; i != 8; ++i) {
      auto RK_i = SIMD_8x32::load_le128(&RK[28 - 4 * i]).rev_words();
      B0 = sm4_x86_rnds4(B0, RK_i);
      B1 = sm4_x86_rnds4(B1, RK_i);
      B2 = sm4_x86_rnds4(B2, RK_i);
      B3 = sm4_x86_rnds4(B3, RK_i);
   }

   B0.reverse().store_le(out);
   B1.reverse().store_le(out + 32);
   B2.reverse().store_le(out + 64);
   B3.reverse().store_le(out + 96);
}

}  // namespace

void BOTAN_FUNC_ISA("sm4,avx2") SM4::sm4_x86_encrypt(const uint8_t inp[], uint8_t out[], size_t blocks) const {
   while(blocks >= 8) {
      sm4_x86_encrypt_x8(out, inp, m_RK);
      inp += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   while(blocks >= 2) {
      sm4_x86_encrypt_x2(out, inp, m_RK);
      inp += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, inp, blocks * 16);
      sm4_x86_encrypt_x2(obuf, ibuf, m_RK);
      copy_mem(out, obuf, blocks * 16);
   }
}

void BOTAN_FUNC_ISA("sm4,avx2") SM4::sm4_x86_decrypt(const uint8_t inp[], uint8_t out[], size_t blocks) const {
   while(blocks >= 8) {
      sm4_x86_decrypt_x8(out, inp, m_RK);
      inp += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   while(blocks >= 2) {
      sm4_x86_decrypt_x2(out, inp, m_RK);
      inp += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, inp, blocks * 16);
      sm4_x86_decrypt_x2(obuf, ibuf, m_RK);
      copy_mem(out, obuf, blocks * 16);
   }
}

}  // namespace Botan
