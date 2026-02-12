/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/poly1305.h>

#include <botan/internal/isa_extn.h>
#include <immintrin.h>

namespace Botan {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

class SIMD_8x44 final {
   public:
      BOTAN_FN_ISA_AVX512 SIMD_8x44() : m_v(_mm512_setzero_si512()) {}

      static BOTAN_FN_ISA_AVX512 SIMD_8x44 splat(uint64_t x) { return SIMD_8x44(_mm512_set1_epi64(x)); }

      static BOTAN_FN_ISA_AVX512 SIMD_8x44 load(const void* p) {
         return SIMD_8x44(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(p)));
      }

      BOTAN_FN_ISA_AVX512 SIMD_8x44(int e7, int e6, int e5, int e4, int e3, int e2, int e1, int e0) :
            SIMD_8x44(_mm512_set_epi64(e7, e6, e5, e4, e3, e2, e1, e0)) {}

      // Permute across two vectors using index vector
      static BOTAN_FN_ISA_AVX512 SIMD_8x44 permute2(const SIMD_8x44& idx, const SIMD_8x44& a, const SIMD_8x44& b) {
         return SIMD_8x44(_mm512_permutex2var_epi64(a.m_v, idx.m_v, b.m_v));
      }

      static BOTAN_FN_ISA_AVX512 SIMD_8x44 permute3(
         const SIMD_8x44& idx0, const SIMD_8x44& idx1, const SIMD_8x44& a, const SIMD_8x44& b, const SIMD_8x44& c) {
         return SIMD_8x44::permute2(idx1, SIMD_8x44::permute2(idx0, a, b), c);
      }

      // VBMI2 double shift right: concatenate (b:a) and shift right by count
      template <int COUNT>
      static BOTAN_FN_ISA_AVX512 SIMD_8x44 shrdi(const SIMD_8x44& a, const SIMD_8x44& b) {
         return SIMD_8x44(_mm512_shrdi_epi64(a.m_v, b.m_v, COUNT));
      }

      BOTAN_FN_ISA_AVX512 SIMD_8x44 add_lane_zero(uint64_t b) {
         return SIMD_8x44(_mm512_mask_add_epi64(m_v, 0x01, m_v, _mm512_set1_epi64(b)));
      }

      // IFMA: accumulator += (a * b) low 52 bits
      BOTAN_FN_ISA_AVX512 SIMD_8x44& ifma_lo(const SIMD_8x44& a, const SIMD_8x44& b) {
         m_v = _mm512_madd52lo_epu64(m_v, a.m_v, b.m_v);
         return *this;
      }

      // IFMA: accumulator += (a * b) high 52 bits
      BOTAN_FN_ISA_AVX512 SIMD_8x44& ifma_hi(const SIMD_8x44& a, const SIMD_8x44& b) {
         m_v = _mm512_madd52hi_epu64(m_v, a.m_v, b.m_v);
         return *this;
      }

      // Multiply by 20: 20*x = (x << 4) + (x << 2)
      BOTAN_FN_ISA_AVX512 SIMD_8x44 mul_20() const {
         return SIMD_8x44(_mm512_add_epi64(_mm512_slli_epi64(m_v, 4), _mm512_slli_epi64(m_v, 2)));
      }

      template <size_t S>
      BOTAN_FN_ISA_AVX512 SIMD_8x44 shr() const {
         return SIMD_8x44(_mm512_srli_epi64(m_v, S));
      }

      BOTAN_FN_ISA_AVX512 uint64_t horizontal_add() const { return _mm512_reduce_add_epi64(m_v); }

      BOTAN_FN_ISA_AVX512 SIMD_8x44 operator&(const SIMD_8x44& other) const {
         return SIMD_8x44(_mm512_and_si512(m_v, other.m_v));
      }

      BOTAN_FN_ISA_AVX512 SIMD_8x44 operator|(const SIMD_8x44& other) const {
         return SIMD_8x44(_mm512_or_si512(m_v, other.m_v));
      }

      static BOTAN_FN_ISA_AVX512 void interleave_3x8(SIMD_8x44& r0, SIMD_8x44& r1, SIMD_8x44& r2) {
         const auto idx1_z0 = SIMD_8x44(0, 3, 6, 9, 12, 15, -1, -1);
         const auto idx2_z0 = SIMD_8x44(7, 6, 5, 4, 3, 2, 10, 13);
         const auto idx1_z1 = SIMD_8x44(1, 4, 7, 10, 13, -1, -1, -1);
         const auto idx2_z1 = SIMD_8x44(7, 6, 5, 4, 3, 8, 11, 14);
         const auto idx1_z2 = SIMD_8x44(2, 5, 8, 11, 14, -1, -1, -1);
         const auto idx2_z2 = SIMD_8x44(7, 6, 5, 4, 3, 9, 12, 15);

         // NOLINTBEGIN(*-suspicious-call-argument)
         auto z0 = SIMD_8x44::permute3(idx1_z0, idx2_z0, r0, r1, r2);
         auto z1 = SIMD_8x44::permute3(idx1_z1, idx2_z1, r0, r1, r2);
         auto z2 = SIMD_8x44::permute3(idx1_z2, idx2_z2, r0, r1, r2);
         // NOLINTEND(*-suspicious-call-argument)

         r0 = z0;
         r1 = z1;
         r2 = z2;
      }

   private:
      __m512i BOTAN_FN_ISA_AVX512 raw() const { return m_v; }

      explicit BOTAN_FN_ISA_AVX512 SIMD_8x44(__m512i v) : m_v(v) {}

      __m512i m_v;
};

// NOLINTEND(portability-simd-intrinsics)

}  // namespace

/*
* Process 8 blocks at a time using AVX-512 IFMA
* h = (h + m[0]) * r^8 + m[1] * r^7 + ... + m[7] * r
*/
size_t BOTAN_FN_ISA_AVX512 Poly1305::poly1305_avx512_blocks(secure_vector<uint64_t>& X,
                                                            const uint8_t* m,
                                                            size_t blocks) {
   constexpr uint64_t M44 = 0xFFFFFFFFFFF;
   constexpr uint64_t M42 = 0x3FFFFFFFFFF;
   constexpr uint64_t hibit64 = static_cast<uint64_t>(1) << 40;

   if(blocks < 8) {
      return 0;
   }

   const size_t original_blocks = blocks;

   // Load h from state
   uint64_t h0 = X[2];
   uint64_t h1 = X[3];
   uint64_t h2 = X[4];

   SIMD_8x44 r0 = SIMD_8x44::load(&X[5]);
   SIMD_8x44 r1 = SIMD_8x44::load(&X[5 + 8]);
   SIMD_8x44 r2 = SIMD_8x44::load(&X[5 + 2 * 8]);
   SIMD_8x44::interleave_3x8(r0, r1, r2);

   const auto s1 = r1.mul_20();
   const auto s2 = r2.mul_20();

   // Constants for vectorized message loading
   // Deinterleave indices: separate low (t0) and high (t1) 64-bit halves of each 128-bit block
   // Memory layout: [t0_0, t1_0, t0_1, t1_1, ...] -> want [t0_0..t0_7] and [t1_0..t1_7]
   const auto idx_lo = SIMD_8x44(14, 12, 10, 8, 6, 4, 2, 0);
   const auto idx_hi = SIMD_8x44(15, 13, 11, 9, 7, 5, 3, 1);
   const auto mask44 = SIMD_8x44::splat(M44);
   const auto mask42 = SIMD_8x44::splat(M42);
   const auto hibit = SIMD_8x44::splat(hibit64);

   while(blocks >= 8) {
      // Load 8 message blocks (128 bytes) with two 512-bit loads
      const auto data0 = SIMD_8x44::load(m);
      const auto data1 = SIMD_8x44::load(m + 64);

      // Deinterleave: separate low and high 64-bit halves of each 128-bit block
      const auto t0 = SIMD_8x44::permute2(idx_lo, data0, data1);
      const auto t1 = SIMD_8x44::permute2(idx_hi, data0, data1);

      // Convert to radix 2^44 representation using VBMI2
      // limb0 = t0[43:0]
      // limb1 = t1[23:0]:t0[63:44] (bits 44-87 of block)
      // limb2 = t1[63:24] | hibit (bits 88-129 of block + high bit)
      auto m0 = t0 & mask44;
      auto m1 = SIMD_8x44::shrdi<44>(t0, t1) & mask44;
      auto m2 = (t1.shr<24>() & mask42) | hibit;

      // Add h to first block
      m0 = m0.add_lane_zero(h0);
      m1 = m1.add_lane_zero(h1);
      m2 = m2.add_lane_zero(h2);

      // d0 = m0*r0 + m1*s2 + m2*s1
      const SIMD_8x44 d0_lo = SIMD_8x44().ifma_lo(m0, r0).ifma_lo(m1, s2).ifma_lo(m2, s1);
      const SIMD_8x44 d0_hi = SIMD_8x44().ifma_hi(m0, r0).ifma_hi(m1, s2).ifma_hi(m2, s1);

      // d1 = m0*r1 + m1*r0 + m2*s2
      const SIMD_8x44 d1_lo = SIMD_8x44().ifma_lo(m0, r1).ifma_lo(m1, r0).ifma_lo(m2, s2);
      const SIMD_8x44 d1_hi = SIMD_8x44().ifma_hi(m0, r1).ifma_hi(m1, r0).ifma_hi(m2, s2);

      // d2 = m0*r2 + m1*r1 + m2*r0
      const SIMD_8x44 d2_lo = SIMD_8x44().ifma_lo(m0, r2).ifma_lo(m1, r1).ifma_lo(m2, r0);
      const SIMD_8x44 d2_hi = SIMD_8x44().ifma_hi(m0, r2).ifma_hi(m1, r1).ifma_hi(m2, r0);

      // Horizontal adds can't overflow - at most 8*3*(2**52-1) ~= 2**57
      const uint64_t sum0_lo = d0_lo.horizontal_add();
      const uint64_t sum0_hi = d0_hi.horizontal_add();
      uint64_t sum1_lo = d1_lo.horizontal_add();
      const uint64_t sum1_hi = d1_hi.horizontal_add();
      uint64_t sum2_lo = d2_lo.horizontal_add();
      const uint64_t sum2_hi = d2_hi.horizontal_add();

      h0 = sum0_lo & M44;
      sum1_lo += (sum0_lo >> 44) + (sum0_hi << 8);
      h1 = sum1_lo & M44;
      sum2_lo += (sum1_lo >> 44) + (sum1_hi << 8);
      h2 = sum2_lo & M42;

      // Wrap-around reduction: carry * 5 goes back to h0
      uint64_t carry = ((sum2_lo >> 42) + (sum2_hi << 10)) * 5;
      carry += h0;
      h0 = carry & M44;
      carry >>= 44;
      carry += h1;
      h1 = carry & M44;
      carry >>= 44;
      h2 += carry;

      m += 8 * 16;
      blocks -= 8;
   }

   X[2] = h0;
   X[3] = h1;
   X[4] = h2;

   return (original_blocks - blocks);
}

}  // namespace Botan
