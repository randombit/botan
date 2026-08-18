/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ctr.h>

#include <botan/assert.h>
#include <botan/internal/simd_8x32.h>

namespace Botan {

BOTAN_FN_ISA_SIMD_8X32
size_t CTR_BE::ctr_proc_bs16_ctr4_simd8x32(const uint8_t* in, uint8_t* out, size_t length) {
   BOTAN_ASSERT_NOMSG(m_pad.size() % 64 == 0);
   BOTAN_DEBUG_ASSERT(m_counter.size() == m_pad.size());

   const size_t pad_size = m_pad.size();
   if(length < pad_size) {
      return 0;
   }

   const size_t ctr_blocks = m_ctr_blocks;

   /*
   * Byte swap table that swaps only the counter bytes and not the nonce bytes
   */
   const SIMD_8x32 bswap_ctr(
      0x03020100, 0x07060504, 0x0B0A0908, 0x0C0D0E0F, 0x03020100, 0x07060504, 0x0B0A0908, 0x0C0D0E0F);

   // Load the starting counter value, bswap the counter field itself so we can add
   const SIMD_8x32 starting_ctr = SIMD_8x32::byte_shuffle(SIMD_8x32::load_le128(m_counter.data()), bswap_ctr);

   // Counter is incremented 4 blocks at a time (2 per register, 2 registers)
   const SIMD_8x32 inc4(0, 0, 0, 4);

   const uint32_t N = static_cast<uint32_t>(ctr_blocks);
   SIMD_8x32 batch_ctr0 = starting_ctr + SIMD_8x32(0, 0, 0, N, 0, 0, 0, N + 1);
   SIMD_8x32 batch_ctr1 = starting_ctr + SIMD_8x32(0, 0, 0, N + 2, 0, 0, 0, N + 3);
   const uint8_t* pad_buf = m_pad.data();
   uint8_t* ctr_buf = m_counter.data();

   const size_t ctr_block_quads = ctr_blocks / 4;

   size_t processed = 0;

   while(length >= pad_size) {
      for(size_t i = 0; i != ctr_block_quads; ++i) {
         const size_t off = i * 64;

         // Store and update the counters
         SIMD_8x32::byte_shuffle(batch_ctr0, bswap_ctr).store_le(ctr_buf + off);
         SIMD_8x32::byte_shuffle(batch_ctr1, bswap_ctr).store_le(ctr_buf + off + 32);
         batch_ctr0 += inc4;
         batch_ctr1 += inc4;

         const auto p0 = SIMD_8x32::load_le(pad_buf + off);
         const auto p1 = SIMD_8x32::load_le(pad_buf + off + 32);

         auto i0 = SIMD_8x32::load_le(in + off);
         auto i1 = SIMD_8x32::load_le(in + off + 32);

         i0 ^= p0;
         i1 ^= p1;

         i0.store_le(out + off);
         i1.store_le(out + off + 32);
      }

      in += pad_size;
      out += pad_size;
      length -= pad_size;
      processed += pad_size;

      // Regenerate the pad buffer
      m_cipher->encrypt_n(m_counter.data(), m_pad.data(), ctr_blocks);
   }

   return processed;
}

}  // namespace Botan
