/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/poly1305.h>

#include <botan/internal/isa_extn.h>
#include <immintrin.h>

namespace Botan {

// NOLINTBEGIN(portability-simd-intrinsics)

namespace {

constexpr uint32_t MASK26 = 0x3FFFFFF;

/*
* 4x26 values packed in a 256-bit register
*
* The 26 bit is somewhat a lie; we actually use the full 64 bit width
* but assume that after a 32x32->64 multiply there is still enough
* space to store sums into 64 bits. We could pack slightly more bits,
* but 26x5 = 130 is enough.
*/
class SIMD_4x26 final {
   public:
      BOTAN_FN_ISA_AVX2 SIMD_4x26() : m_v(_mm256_setzero_si256()) {}

      // Construct from raw __m256i (for vectorized loading)
      static BOTAN_FN_ISA_AVX2 SIMD_4x26 from_raw(__m256i v) { return SIMD_4x26(v); }

      // Pack 4 values into lanes (high to low: v3, v2, v1, v0)
      static BOTAN_FN_ISA_AVX2 SIMD_4x26 set(uint32_t v3, uint32_t v2, uint32_t v1, uint32_t v0) {
         return SIMD_4x26(_mm256_set_epi32(0, v3, 0, v2, 0, v1, 0, v0));
      }

      // Multiply by 5: 5*x = (x << 2) + x
      BOTAN_FN_ISA_AVX2 SIMD_4x26 mul_5() const { return SIMD_4x26(_mm256_add_epi32(_mm256_slli_epi32(m_v, 2), m_v)); }

      friend SIMD_4x26 BOTAN_FN_ISA_AVX2 operator+(const SIMD_4x26& x, const SIMD_4x26& y) {
         return SIMD_4x26(_mm256_add_epi64(x.raw(), y.raw()));
      }

      friend SIMD_4x26 BOTAN_FN_ISA_AVX2 operator*(const SIMD_4x26& x, const SIMD_4x26& y) {
         return SIMD_4x26(_mm256_mul_epi32(x.raw(), y.raw()));
      }

      // Horizontal sum of 4x64-bit values
      BOTAN_FN_ISA_AVX2 uint64_t horizontal_add64() const {
         uint64_t tmp[4];
         _mm256_storeu_si256(reinterpret_cast<__m256i*>(tmp), m_v);
         return tmp[0] + tmp[1] + tmp[2] + tmp[3];
      }

      __m256i BOTAN_FN_ISA_AVX2 raw() const { return m_v; }

   private:
      explicit BOTAN_FN_ISA_AVX2 SIMD_4x26(__m256i v) : m_v(v) {}

      __m256i m_v;
};

/*
* Vectorized load of 4 message blocks into radix 2^26 representation
*
* Loads 64 bytes (4 blocks), deinterleaves t0/t1 halves, and converts
* to radix 2^26 using vector shift/mask operations.
*
* Lane ordering: block 0 in lane 3, block 3 in lane 0 (reversed for multiply)
*/
BOTAN_FN_ISA_AVX2 void load_4_blocks_26(SIMD_4x26& msg_0,
                                        SIMD_4x26& msg_1,
                                        SIMD_4x26& msg_2,
                                        SIMD_4x26& msg_3,
                                        SIMD_4x26& msg_4,
                                        const uint8_t* m,
                                        std::array<uint32_t, 5> h) {
   // Load 64 bytes (4 blocks of 16 bytes each)
   const __m256i d0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(m));
   const __m256i d1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(m + 32));

   // Deinterleave: extract low 64-bit (t0) and high 64-bit (t1) from each block
   // unpacklo/hi work within 128-bit lanes: pairs adjacent blocks
   const __m256i t0_mixed = _mm256_unpacklo_epi64(d0, d1);  // [blk3_lo, blk1_lo, blk2_lo, blk0_lo]
   const __m256i t1_mixed = _mm256_unpackhi_epi64(d0, d1);  // [blk3_hi, blk1_hi, blk2_hi, blk0_hi]

   const __m256i t0 = _mm256_permute4x64_epi64(t0_mixed, 0b00100111);
   const __m256i t1 = _mm256_permute4x64_epi64(t1_mixed, 0b00100111);

   // Constants for radix conversion
   const __m256i mask26 = _mm256_set1_epi64x(MASK26);
   const __m256i hibit_vec = _mm256_set1_epi64x(1 << 24);

   // Convert to radix 2^26:
   // limb0 = t0[25:0]
   // limb1 = t0[51:26]
   // limb2 = t0[63:52] | t1[13:0] << 12 (bits 52-77)
   // limb3 = t1[39:14] (bits 78-103)
   // limb4 = t1[63:40] | hibit (bits 104-127 + 2^128 marker)
   __m256i limb0 = _mm256_and_si256(t0, mask26);
   __m256i limb1 = _mm256_and_si256(_mm256_srli_epi64(t0, 26), mask26);
   __m256i limb2 = _mm256_and_si256(_mm256_or_si256(_mm256_srli_epi64(t0, 52), _mm256_slli_epi64(t1, 12)), mask26);
   __m256i limb3 = _mm256_and_si256(_mm256_srli_epi64(t1, 14), mask26);
   __m256i limb4 = _mm256_or_si256(_mm256_srli_epi64(t1, 40), hibit_vec);

   // Add h to lane 3 (block 0): h + m[0] before multiply by r^4
   limb0 = _mm256_add_epi64(limb0, _mm256_set_epi64x(h[0], 0, 0, 0));
   limb1 = _mm256_add_epi64(limb1, _mm256_set_epi64x(h[1], 0, 0, 0));
   limb2 = _mm256_add_epi64(limb2, _mm256_set_epi64x(h[2], 0, 0, 0));
   limb3 = _mm256_add_epi64(limb3, _mm256_set_epi64x(h[3], 0, 0, 0));
   limb4 = _mm256_add_epi64(limb4, _mm256_set_epi64x(h[4], 0, 0, 0));

   msg_0 = SIMD_4x26::from_raw(limb0);
   msg_1 = SIMD_4x26::from_raw(limb1);
   msg_2 = SIMD_4x26::from_raw(limb2);
   msg_3 = SIMD_4x26::from_raw(limb3);
   msg_4 = SIMD_4x26::from_raw(limb4);
}

// NOLINTEND(portability-simd-intrinsics)

// Convert radix-2^26 limbs back to radix-2^44
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 void convert_26_to_44(uint64_t& r0,
                                                           uint64_t& r1,
                                                           uint64_t& r2,
                                                           const std::array<uint32_t, 5> in) {
   constexpr uint64_t M44 = 0xFFFFFFFFFFF;
   constexpr uint64_t M42 = 0x3FFFFFFFFFF;

   // Expand to 64 bits
   const uint64_t i0 = in[0];
   const uint64_t i1 = in[1];
   const uint64_t i2 = in[2];
   const uint64_t i3 = in[3];
   const uint64_t i4 = in[4];

   r0 = (i0 | (i1 << 26)) & M44;
   r1 = ((i1 >> 18) | (i2 << 8) | (i3 << 34)) & M44;
   r2 = ((i3 >> 10) | (i4 << 16)) & M42;
}

// Convert radix-2^44 limbs to radix-2^26
BOTAN_FORCE_INLINE std::array<uint32_t, 5> convert_44_to_26(uint64_t r0, uint64_t r1, uint64_t r2) {
   std::array<uint32_t, 5> out{};
   out[0] = static_cast<uint32_t>(r0) & MASK26;                       // bits 0-25
   out[1] = static_cast<uint32_t>((r0 >> 26) | (r1 << 18)) & MASK26;  // bits 26-51
   out[2] = static_cast<uint32_t>(r1 >> 8) & MASK26;                  // bits 52-77
   out[3] = static_cast<uint32_t>((r1 >> 34) | (r2 << 10)) & MASK26;  // bits 78-103
   out[4] = static_cast<uint32_t>(r2 >> 16) & MASK26;                 // bits 104-129
   return out;
}

inline void BOTAN_FN_ISA_AVX2
load_r(SIMD_4x26& r0, SIMD_4x26& r1, SIMD_4x26& r2, SIMD_4x26& r3, SIMD_4x26& r4, const secure_vector<uint64_t>& X) {
   // TODO do this in vector registers instead
   const auto t = convert_44_to_26(X[5], X[6], X[7]);
   const auto t2 = convert_44_to_26(X[8], X[9], X[10]);
   const auto t3 = convert_44_to_26(X[11], X[12], X[13]);
   const auto t4 = convert_44_to_26(X[14], X[15], X[16]);

   r0 = SIMD_4x26::set(t4[0], t3[0], t2[0], t[0]);
   r1 = SIMD_4x26::set(t4[1], t3[1], t2[1], t[1]);
   r2 = SIMD_4x26::set(t4[2], t3[2], t2[2], t[2]);
   r3 = SIMD_4x26::set(t4[3], t3[3], t2[3], t[3]);
   r4 = SIMD_4x26::set(t4[4], t3[4], t2[4], t[4]);
}

}  // namespace

/*
* Process 4 blocks at a time using AVX2
* h = (h + m[0]) * r^4 + m[1] * r^3 + m[2] * r^2 + m[3] * r
*/
size_t BOTAN_FN_ISA_AVX2 Poly1305::poly1305_avx2_blocks(secure_vector<uint64_t>& X, const uint8_t m[], size_t blocks) {
   if(blocks < 4) {
      return 0;
   }

   const size_t incoming_blocks = blocks;

   auto h = convert_44_to_26(X[2], X[3], X[4]);

   SIMD_4x26 r0;
   SIMD_4x26 r1;
   SIMD_4x26 r2;
   SIMD_4x26 r3;
   SIMD_4x26 r4;
   load_r(r0, r1, r2, r3, r4, X);

   const auto r1_5 = r1.mul_5();
   const auto r2_5 = r2.mul_5();
   const auto r3_5 = r3.mul_5();
   const auto r4_5 = r4.mul_5();

   while(blocks >= 4) {
      // Load 4 message blocks, convert to radix 2^26, and add h to block 0
      SIMD_4x26 m0;
      SIMD_4x26 m1;
      SIMD_4x26 m2;
      SIMD_4x26 m3;
      SIMD_4x26 m4;
      load_4_blocks_26(m0, m1, m2, m3, m4, m, h);

      const auto d0 = m0 * r0 + m1 * r4_5 + m2 * r3_5 + m3 * r2_5 + m4 * r1_5;
      const auto d1 = m0 * r1 + m1 * r0 + m2 * r4_5 + m3 * r3_5 + m4 * r2_5;
      const auto d2 = m0 * r2 + m1 * r1 + m2 * r0 + m3 * r4_5 + m4 * r3_5;
      const auto d3 = m0 * r3 + m1 * r2 + m2 * r1 + m3 * r0 + m4 * r4_5;
      const auto d4 = m0 * r4 + m1 * r3 + m2 * r2 + m3 * r1 + m4 * r0;

      const uint64_t h0_64 = d0.horizontal_add64();
      uint64_t h1_64 = d1.horizontal_add64();
      uint64_t h2_64 = d2.horizontal_add64();
      uint64_t h3_64 = d3.horizontal_add64();
      uint64_t h4_64 = d4.horizontal_add64();

      h1_64 += h0_64 >> 26;
      h[0] = static_cast<uint32_t>(h0_64) & MASK26;
      h2_64 += h1_64 >> 26;
      h[1] = static_cast<uint32_t>(h1_64) & MASK26;
      h3_64 += h2_64 >> 26;
      h[2] = static_cast<uint32_t>(h2_64) & MASK26;
      h4_64 += h3_64 >> 26;
      h[3] = static_cast<uint32_t>(h3_64) & MASK26;

      const uint64_t c = h4_64 >> 26;
      h[4] = static_cast<uint32_t>(h4_64) & MASK26;

      uint64_t carry = c * 5;
      carry += h[0];
      h[0] = static_cast<uint32_t>(carry) & MASK26;
      carry >>= 26;
      carry += h[1];
      h[1] = static_cast<uint32_t>(carry) & MASK26;
      carry >>= 26;
      carry += h[2];
      h[2] = static_cast<uint32_t>(carry) & MASK26;
      carry >>= 26;
      carry += h[3];
      h[3] = static_cast<uint32_t>(carry) & MASK26;
      carry >>= 26;
      h[4] += static_cast<uint32_t>(carry);

      m += 64;
      blocks -= 4;
   }

   convert_26_to_44(X[2], X[3], X[4], h);

   return (incoming_blocks - blocks);
}

}  // namespace Botan
