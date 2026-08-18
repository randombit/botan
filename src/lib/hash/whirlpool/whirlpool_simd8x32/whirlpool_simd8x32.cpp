/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/whirlpool.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_8x32.h>

namespace Botan {

namespace WhirlpoolSIMD8x32 {

namespace {

class WhirlpoolState final {
   public:
      BOTAN_FN_ISA_SIMD_8X32
      WhirlpoolState() = default;

      BOTAN_FN_ISA_SIMD_8X32
      WhirlpoolState(SIMD_8x32 lo, SIMD_8x32 hi) : m_lo(lo), m_hi(hi) {}

      WhirlpoolState(const WhirlpoolState& other) = default;
      WhirlpoolState(WhirlpoolState&& other) = default;
      WhirlpoolState& operator=(const WhirlpoolState& other) = default;
      WhirlpoolState& operator=(WhirlpoolState&& other) = default;
      ~WhirlpoolState() = default;

      BOTAN_FN_ISA_SIMD_8X32
      static WhirlpoolState load_bytes(const uint8_t src[64]) {
         return WhirlpoolState(SIMD_8x32::load_le(src), SIMD_8x32::load_le(src + 32));
      }

      BOTAN_FN_ISA_SIMD_8X32
      static WhirlpoolState load_be(const uint64_t src[8]) {
         return WhirlpoolState(SIMD_8x32::load_le(reinterpret_cast<const uint8_t*>(src)),
                               SIMD_8x32::load_le(reinterpret_cast<const uint8_t*>(src + 4)))
            .bswap();
      }

      BOTAN_FN_ISA_SIMD_8X32
      void store_be(uint64_t dst[8]) const {
         auto s = bswap();
         s.m_lo.store_le(reinterpret_cast<uint8_t*>(dst));
         s.m_hi.store_le(reinterpret_cast<uint8_t*>(dst + 4));
      }

      BOTAN_FN_ISA_SIMD_8X32
      inline friend WhirlpoolState operator^(WhirlpoolState a, WhirlpoolState b) {
         return WhirlpoolState(a.m_lo ^ b.m_lo, a.m_hi ^ b.m_hi);
      }

      BOTAN_FN_ISA_SIMD_8X32
      inline friend WhirlpoolState operator^(WhirlpoolState a, uint64_t rc) {
         const SIMD_8x32 rc_v(static_cast<uint32_t>(rc), static_cast<uint32_t>(rc >> 32), 0, 0, 0, 0, 0, 0);
         return WhirlpoolState(a.m_lo ^ rc_v, a.m_hi);
      }

      BOTAN_FN_ISA_SIMD_8X32
      inline WhirlpoolState& operator^=(WhirlpoolState other) {
         m_lo ^= other.m_lo;
         m_hi ^= other.m_hi;
         return *this;
      }

      BOTAN_FN_ISA_SIMD_8X32
      inline WhirlpoolState sub_bytes() const { return WhirlpoolState(sub_bytes(m_lo), sub_bytes(m_hi)); }

      BOTAN_FN_ISA_SIMD_8X32
      inline WhirlpoolState shift_columns() const {
         /*
         * This is a lot more complicated than the AVX-512 version since first we have
         * the state split between two registers and also the byte shuffles only work
         * within 128 bit halves
         */

         // Byte indices with the top bit set are zeroed by the masked shuffle
         constexpr uint32_t non = 0xFF;

         constexpr auto idx = [](uint32_t b0, uint32_t b1, uint32_t b2, uint32_t b3) {
            return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
         };

         // Which bytes are taken from a source depends on both which register and which half it is
         const SIMD_8x32 idx_same_half(
            idx(0x0, non, non, non), idx(non, non, non, 0xF), idx(0x8, 0x1, non, non), idx(non, non, non, non));
         const SIMD_8x32 idx_other_reg(
            idx(non, non, non, 0xB), idx(0x4, non, non, non), idx(non, non, non, non), idx(0xC, 0x5, non, non));
         const SIMD_8x32 idx_other_half(idx(non, non, non, non),
                                        idx(non, 0xD, 0x6, non),
                                        idx(non, non, non, non),
                                        idx(non, non, 0xE, 0x7),
                                        idx(non, 0x9, 0x2, non),
                                        idx(non, non, non, non),
                                        idx(non, non, 0xA, 0x3),
                                        idx(non, non, non, non));
         const SIMD_8x32 idx_other_both(idx(non, 0x9, 0x2, non),
                                        idx(non, non, non, non),
                                        idx(non, non, 0xA, 0x3),
                                        idx(non, non, non, non),
                                        idx(non, non, non, non),
                                        idx(non, 0xD, 0x6, non),
                                        idx(non, non, non, non),
                                        idx(non, non, 0xE, 0x7));

         // Swap the two halves within the registers so we can get at the values we need via in-half shuffles
         const auto r_lo = m_lo.swap_halves();
         const auto r_hi = m_hi.swap_halves();

         /*
         * Compute the shift column output by shuffling all 4 input halves (lo[0], lo[1], hi[0], hi[1])
         * to select out the values we want from each source half, placing them in the
         * index we want, and OR each into the result.
         */
         SIMD_8x32 new_lo = SIMD_8x32::masked_byte_shuffle(m_lo, idx_same_half);
         new_lo |= SIMD_8x32::masked_byte_shuffle(r_lo, idx_other_half);
         new_lo |= SIMD_8x32::masked_byte_shuffle(m_hi, idx_other_reg);
         new_lo |= SIMD_8x32::masked_byte_shuffle(r_hi, idx_other_both);

         // Same as above just with hi/lo swapped
         SIMD_8x32 new_hi = SIMD_8x32::masked_byte_shuffle(m_hi, idx_same_half);
         new_hi |= SIMD_8x32::masked_byte_shuffle(r_hi, idx_other_half);
         new_hi |= SIMD_8x32::masked_byte_shuffle(m_lo, idx_other_reg);
         new_hi |= SIMD_8x32::masked_byte_shuffle(r_lo, idx_other_both);

         return WhirlpoolState(new_lo, new_hi);
      }

      BOTAN_FN_ISA_SIMD_8X32
      BOTAN_FORCE_INLINE WhirlpoolState mix_rows() const { return WhirlpoolState(mix_rows(m_lo), mix_rows(m_hi)); }

      BOTAN_FN_ISA_SIMD_8X32
      BOTAN_FORCE_INLINE WhirlpoolState round() const { return sub_bytes().shift_columns().mix_rows(); }

   private:
      /*
      * The Whirlpool 8-bit Sbox is built out of 4-bit sboxes, which can be
      * individually computed using byte shuffles.
      */
      BOTAN_FORCE_INLINE BOTAN_FN_ISA_SIMD_8X32 static SIMD_8x32 sub_bytes(SIMD_8x32 v) {
         const SIMD_8x32 Ebox(0x0C090B01, 0x030F060D, 0x0407080E, 0x0005020A);
         const SIMD_8x32 Eibox(0x070D000F, 0x0A050E0B, 0x010C0209, 0x06080403);
         const SIMD_8x32 Rbox(0x0D0B0C07, 0x0F09040E, 0x0A080306, 0x00010502);

         const auto lo_mask = SIMD_8x32::splat(0x0F0F0F0F);

         const auto lo_nib = v & lo_mask;
         const auto hi_nib = v.shr<4>() & lo_mask;

         // L = Ebox[hi], R = Eibox[lo], T = Rbox[L ^ R]
         const auto L = SIMD_8x32::byte_shuffle(Ebox, hi_nib);
         const auto R = SIMD_8x32::byte_shuffle(Eibox, lo_nib);
         const auto T = SIMD_8x32::byte_shuffle(Rbox, L ^ R);

         // result = (Ebox[L ^ T] << 4) | Eibox[R ^ T]
         const auto out_hi = SIMD_8x32::byte_shuffle(Ebox, L ^ T);
         const auto out_lo = SIMD_8x32::byte_shuffle(Eibox, R ^ T);

         return out_hi.shl<4>() | out_lo;
      }

      BOTAN_FORCE_INLINE BOTAN_FN_ISA_SIMD_8X32 static SIMD_8x32 mix_rows(SIMD_8x32 v) {
         // Shuffles for 64-bit rotations by multiples of 8 bits
         const SIMD_8x32 rot1(0x02010007, 0x06050403, 0x0A09080F, 0x0E0D0C0B);
         const SIMD_8x32 rot2(0x01000706, 0x05040302, 0x09080F0E, 0x0D0C0B0A);
         const SIMD_8x32 rot3(0x00070605, 0x04030201, 0x080F0E0D, 0x0C0B0A09);
         const SIMD_8x32 rot4(0x07060504, 0x03020100, 0x0F0E0D0C, 0x0B0A0908);
         const SIMD_8x32 rot5(0x06050403, 0x02010007, 0x0E0D0C0B, 0x0A09080F);
         const SIMD_8x32 rot6(0x05040302, 0x01000706, 0x0D0C0B0A, 0x09080F0E);
         const SIMD_8x32 rot7(0x04030201, 0x00070605, 0x0C0B0A09, 0x080F0E0D);

         const auto x2 = v.xtime<0x1D>();
         const auto x4 = x2.xtime<0x1D>();
         const auto x8 = x4.xtime<0x1D>();
         const auto x5 = x4 ^ v;
         const auto x9 = x8 ^ v;

         const auto t01 = v ^ SIMD_8x32::byte_shuffle(v, rot1);
         const auto t23 = SIMD_8x32::byte_shuffle(x4, rot2) ^ SIMD_8x32::byte_shuffle(v, rot3);
         const auto t45 = SIMD_8x32::byte_shuffle(x8, rot4) ^ SIMD_8x32::byte_shuffle(x5, rot5);
         const auto t67 = SIMD_8x32::byte_shuffle(x2, rot6) ^ SIMD_8x32::byte_shuffle(x9, rot7);

         return (t01 ^ t23) ^ (t45 ^ t67);
      }

      BOTAN_FN_ISA_SIMD_8X32
      WhirlpoolState bswap() const {
         // 64-bit byteswap
         const SIMD_8x32 tbl(0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B);
         return WhirlpoolState(SIMD_8x32::byte_shuffle(m_lo, tbl), SIMD_8x32::byte_shuffle(m_hi, tbl));
      }

      SIMD_8x32 m_lo;
      SIMD_8x32 m_hi;
};

}  // namespace

}  // namespace WhirlpoolSIMD8x32

BOTAN_FN_ISA_SIMD_8X32
void Whirlpool::compress_n_simd8x32(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using WhirlpoolSIMD8x32::WhirlpoolState;

   auto H = WhirlpoolState::load_be(digest.data());

   for(size_t i = 0; i != blocks; ++i) {
      const auto M = WhirlpoolState::load_bytes(input.data() + i * 64);

      auto K = H;
      H ^= M;
      auto B = H;  // B = M ^ K

      K = K.round() ^ 0x4F01B887E8C62318;
      B = B.round() ^ K;

      K = K.round() ^ 0x52916F79F5D2A636;
      B = B.round() ^ K;

      K = K.round() ^ 0x357B0CA38E9BBC60;
      B = B.round() ^ K;

      K = K.round() ^ 0x57FE4B2EC2D7E01D;
      B = B.round() ^ K;

      K = K.round() ^ 0xDA4AF09FE5377715;
      B = B.round() ^ K;

      K = K.round() ^ 0x856BA0B10A29C958;
      B = B.round() ^ K;

      K = K.round() ^ 0x67053ECBF4105DBD;
      B = B.round() ^ K;

      K = K.round() ^ 0xD8957DA78B4127E4;
      B = B.round() ^ K;

      K = K.round() ^ 0x9E4717DD667CEEFB;
      B = B.round() ^ K;

      K = K.round() ^ 0x33835AAD07BF2DCA;
      B = B.round() ^ K;

      H ^= B;
   }

   H.store_be(digest.data());
}

}  // namespace Botan
