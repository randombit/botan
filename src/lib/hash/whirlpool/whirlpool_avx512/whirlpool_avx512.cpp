/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/whirlpool.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/whirlpool_consts.h>
#include <immintrin.h>

namespace Botan {

namespace WhirlpoolAVX512 {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

class WhirlpoolState final {
   public:
      BOTAN_FN_ISA_AVX512
      WhirlpoolState() : m_v(_mm512_setzero_si512()) {}

      BOTAN_FN_ISA_AVX512
      explicit WhirlpoolState(__m512i v) : m_v(v) {}

      WhirlpoolState(const WhirlpoolState& other) = default;
      WhirlpoolState(WhirlpoolState&& other) = default;
      WhirlpoolState& operator=(const WhirlpoolState& other) = default;
      WhirlpoolState& operator=(WhirlpoolState&& other) = default;
      ~WhirlpoolState() = default;

      // Load 64 bytes of message data
      BOTAN_FN_ISA_AVX512
      static WhirlpoolState load_bytes(const uint8_t src[64]) { return WhirlpoolState(_mm512_loadu_si512(src)); }

      BOTAN_FN_ISA_AVX512
      static WhirlpoolState load_be(const uint64_t src[8]) { return WhirlpoolState(_mm512_loadu_si512(src)).bswap(); }

      BOTAN_FN_ISA_AVX512
      void store_be(uint64_t dst[8]) const { _mm512_storeu_si512(dst, bswap().m_v); }

      BOTAN_FN_ISA_AVX512
      inline friend WhirlpoolState operator^(WhirlpoolState a, WhirlpoolState b) {
         return WhirlpoolState(_mm512_xor_si512(a.m_v, b.m_v));
      }

      BOTAN_FN_ISA_AVX512
      inline WhirlpoolState& operator^=(WhirlpoolState other) {
         m_v = _mm512_xor_si512(m_v, other.m_v);
         return *this;
      }

      /*
      * The Whirlpool 8-bit Sbox is built out of 4-bit sboxes, which can be
      * individually computed using pshufb-style shuffles.
      */
      BOTAN_FN_ISA_AVX512
      inline WhirlpoolState sub_bytes() const {
         const __m512i Ebox =
            _mm512_broadcast_i32x4(_mm_setr_epi8(1, 11, 9, 12, 13, 6, 15, 3, 14, 8, 7, 4, 10, 2, 5, 0));
         const __m512i Eibox =
            _mm512_broadcast_i32x4(_mm_setr_epi8(15, 0, 13, 7, 11, 14, 5, 10, 9, 2, 12, 1, 3, 4, 8, 6));
         const __m512i Rbox =
            _mm512_broadcast_i32x4(_mm_setr_epi8(7, 12, 11, 13, 14, 4, 9, 15, 6, 3, 8, 10, 2, 5, 1, 0));

         const __m512i lo_mask = _mm512_set1_epi8(0x0F);

         const __m512i lo_nib = _mm512_and_si512(m_v, lo_mask);
         const __m512i hi_nib = _mm512_and_si512(_mm512_srli_epi16(m_v, 4), lo_mask);

         // L = Ebox[hi], R = Eibox[lo], T = Rbox[L ^ R]
         const __m512i L = _mm512_shuffle_epi8(Ebox, hi_nib);
         const __m512i R = _mm512_shuffle_epi8(Eibox, lo_nib);
         const __m512i T = _mm512_shuffle_epi8(Rbox, _mm512_xor_si512(L, R));

         // result = (Ebox[L ^ T] << 4) | Eibox[R ^ T]
         const __m512i out_hi = _mm512_shuffle_epi8(Ebox, _mm512_xor_si512(L, T));
         const __m512i out_lo = _mm512_shuffle_epi8(Eibox, _mm512_xor_si512(R, T));

         return WhirlpoolState(_mm512_or_si512(_mm512_slli_epi16(out_hi, 4), _mm512_and_si512(out_lo, lo_mask)));
      }

      /*
      * ShiftColumns: column j is cyclically shifted down by j positions.
      *
      * For output row r, column c: source = row (r - c + 8) % 8, column c.
      * Implemented as a single vpermb with a fixed 64-byte permutation.
      */
      BOTAN_FN_ISA_AVX512
      inline WhirlpoolState shift_columns() const {
         // Register byte for (row r, col c) = r*8 + c
         // Source byte = ((r - c + 8) % 8) * 8 + c
         alignas(64) static constexpr uint8_t perm[64] = {
            // clang-format off
             0*8+0, 7*8+1, 6*8+2, 5*8+3, 4*8+4, 3*8+5, 2*8+6, 1*8+7,
             1*8+0, 0*8+1, 7*8+2, 6*8+3, 5*8+4, 4*8+5, 3*8+6, 2*8+7,
             2*8+0, 1*8+1, 0*8+2, 7*8+3, 6*8+4, 5*8+5, 4*8+6, 3*8+7,
             3*8+0, 2*8+1, 1*8+2, 0*8+3, 7*8+4, 6*8+5, 5*8+6, 4*8+7,
             4*8+0, 3*8+1, 2*8+2, 1*8+3, 0*8+4, 7*8+5, 6*8+6, 5*8+7,
             5*8+0, 4*8+1, 3*8+2, 2*8+3, 1*8+4, 0*8+5, 7*8+6, 6*8+7,
             6*8+0, 5*8+1, 4*8+2, 3*8+3, 2*8+4, 1*8+5, 0*8+6, 7*8+7,
             7*8+0, 6*8+1, 5*8+2, 4*8+3, 3*8+4, 2*8+5, 1*8+6, 0*8+7,
            // clang-format on
         };
         return WhirlpoolState(_mm512_permutexvar_epi8(_mm512_load_si512(perm), m_v));
      }

      /*
      * MixRows: MDS circulant [1, 1, 4, 1, 8, 5, 2, 9] over GF(2^8) mod 0x11D
      *
      * Since the MDS coefficients are so small we can easily compute them using
      * a few xtimes plus additions (aka XOR)
      */
      BOTAN_FN_ISA_AVX512
      inline WhirlpoolState mix_rows() const {
         /*
         Constants for quadword rotations by X bytes.

         Could use _mm512_rol_epi64 for this, but it's oddly slower even though
         all documentation suggests that both instructions have the same latency
         and throughput.
         */
         const __m512i rot1 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14));
         const __m512i rot2 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(6, 7, 0, 1, 2, 3, 4, 5, 14, 15, 8, 9, 10, 11, 12, 13));
         const __m512i rot3 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(5, 6, 7, 0, 1, 2, 3, 4, 13, 14, 15, 8, 9, 10, 11, 12));
         const __m512i rot4 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11));
         const __m512i rot5 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10));
         const __m512i rot6 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9));
         const __m512i rot7 =
            _mm512_broadcast_i32x4(_mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8));

         const __m512i x2 = xtime(m_v);
         const __m512i x4 = xtime(x2);
         const __m512i x8 = xtime(x4);
         const __m512i x5 = _mm512_xor_si512(x4, m_v);
         const __m512i x9 = _mm512_xor_si512(x8, m_v);

         const __m512i t01 = _mm512_xor_si512(m_v, _mm512_shuffle_epi8(m_v, rot1));
         const __m512i t23 = _mm512_xor_si512(_mm512_shuffle_epi8(x4, rot2), _mm512_shuffle_epi8(m_v, rot3));
         const __m512i t45 = _mm512_xor_si512(_mm512_shuffle_epi8(x8, rot4), _mm512_shuffle_epi8(x5, rot5));
         const __m512i t67 = _mm512_xor_si512(_mm512_shuffle_epi8(x2, rot6), _mm512_shuffle_epi8(x9, rot7));

         return WhirlpoolState(_mm512_xor_si512(_mm512_xor_si512(t01, t23), _mm512_xor_si512(t45, t67)));
      }

      /*
      * Whirlpool round: SubBytes -> ShiftColumns -> MixRows
      */
      BOTAN_FN_ISA_AVX512
      inline WhirlpoolState round() const { return sub_bytes().shift_columns().mix_rows(); }

      // Round constant
      BOTAN_FN_ISA_AVX512
      static inline WhirlpoolState rc(uint64_t v) { return WhirlpoolState(_mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, v)); }

   private:
      BOTAN_FN_ISA_AVX512
      WhirlpoolState bswap() const {
         const __m512i tbl = _mm512_broadcast_i32x4(_mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7));

         return WhirlpoolState(_mm512_shuffle_epi8(m_v, tbl));
      }

      // Packed 16-wide doubling in GF(2^8) mod 0x11D
      BOTAN_FN_ISA_AVX512
      static __m512i xtime(__m512i a) {
         const __m512i poly = _mm512_set1_epi8(0x1D);
         const __mmask64 top_bits = _mm512_movepi8_mask(a);
         const __m512i shifted = _mm512_add_epi8(a, a);  // no 8-bit shift in AVX512
         return _mm512_mask_blend_epi8(top_bits, shifted, _mm512_xor_si512(shifted, poly));
      }

      __m512i m_v;
};

// NOLINTEND(portability-simd-intrinsics)

}  // namespace

}  // namespace WhirlpoolAVX512

BOTAN_FN_ISA_AVX512
void Whirlpool::compress_n_avx512(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using WhirlpoolAVX512::WhirlpoolState;

   auto H = WhirlpoolState::load_be(digest.data());

   constexpr auto WHIRL_RC = whirlpool_rc<true>(whirlpool_sbox());

   for(size_t i = 0; i != blocks; ++i) {
      const auto M = WhirlpoolState::load_bytes(input.data() + i * 64);

      auto K = H;
      H ^= M;
      auto B = H;  // B = M ^ K

      for(size_t r = 0; r != 10; ++r) {
         K = K.round() ^ WhirlpoolState::rc(WHIRL_RC[r]);
         B = B.round() ^ K;
      }

      H ^= B;
   }

   H.store_be(digest.data());
}

}  // namespace Botan
