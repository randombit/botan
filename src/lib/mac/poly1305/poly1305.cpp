/*
* Derived from poly1305-donna-64.h by Andrew Moon <liquidsun@gmail.com>
* in https://github.com/floodyberry/poly1305-donna
*
* (C) 2014 Andrew Moon
* (C) 2014,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/poly1305.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/donna128.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_HAS_POLY1305_AVX2) || defined(BOTAN_HAS_POLY1305_AVX512)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

// State layout: pad || accum || r || r^2 || r^3 || ... || r^n
// This ordering allows extending with more powers of r at the end
constexpr size_t PAD_BASE = 0;  // pad[0..1]
constexpr size_t H_BASE = 2;    // h[0..2] (accumulator)
constexpr size_t R_BASE = 5;    // r^1[0..2], r^2[3..5], r^3[6..8], etc.

// Multiply two values in radix 2^44 representation mod (2^130 - 5)
// h = a * b mod p
BOTAN_FORCE_INLINE void poly1305_mul_44(uint64_t& h0,
                                        uint64_t& h1,
                                        uint64_t& h2,
                                        uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t b0,
                                        uint64_t b1,
                                        uint64_t b2) {
   constexpr uint64_t M44 = 0xFFFFFFFFFFF;
   constexpr uint64_t M42 = 0x3FFFFFFFFFF;

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
   typedef donna128 uint128_t;
#endif

   const uint64_t s1 = b1 * 20;
   const uint64_t s2 = b2 * 20;

   const uint128_t d0 = uint128_t(a0) * b0 + uint128_t(a1) * s2 + uint128_t(a2) * s1;
   const uint64_t c0 = carry_shift(d0, 44);

   const uint128_t d1 = uint128_t(a0) * b1 + uint128_t(a1) * b0 + uint128_t(a2) * s2 + c0;
   const uint64_t c1 = carry_shift(d1, 44);

   const uint128_t d2 = uint128_t(a0) * b2 + uint128_t(a1) * b1 + uint128_t(a2) * b0 + c1;
   const uint64_t c2 = carry_shift(d2, 42);

   h0 = (d0 & M44) + c2 * 5;
   h1 = (d1 & M44) + (h0 >> 44);
   h0 &= M44;
   h2 = d2 & M42;
}

// Extend powers of r from current max to target
void poly1305_extend_powers(secure_vector<uint64_t>& X, size_t target_powers) {
   const size_t current_powers = (X.size() - 5) / 3;

   if(current_powers >= target_powers) {
      return;
   }

   // Load r^1 for multiplication
   const uint64_t r0 = X[R_BASE + 0];
   const uint64_t r1 = X[R_BASE + 1];
   const uint64_t r2 = X[R_BASE + 2];

   X.resize(5 + target_powers * 3);

   // Compute r^(current+1) through r^target
   for(size_t i = current_powers + 1; i <= target_powers; ++i) {
      const size_t offset = R_BASE + (i - 1) * 3;
      poly1305_mul_44(
         X[offset + 0], X[offset + 1], X[offset + 2], X[offset - 3], X[offset - 2], X[offset - 1], r0, r1, r2);
   }
}

// Initialize Poly1305 state and precompute powers of r
void poly1305_init(secure_vector<uint64_t>& X, const uint8_t key[32]) {
   X.clear();
   X.reserve(2 + 3 + 2 * 3);
   X.resize(2 + 3 + 3);

   /* Save pad for later (first 2 slots) */
   X[PAD_BASE + 0] = load_le<uint64_t>(key, 2);
   X[PAD_BASE + 1] = load_le<uint64_t>(key, 3);

   /* h = 0 (accumulator, next 3 slots) */
   X[H_BASE + 0] = 0;
   X[H_BASE + 1] = 0;
   X[H_BASE + 2] = 0;

   /* r &= 0xffffffc0ffffffc0ffffffc0fffffff (clamping) */
   const uint64_t t0 = load_le<uint64_t>(key, 0);
   const uint64_t t1 = load_le<uint64_t>(key, 1);

   const uint64_t r0 = (t0) & 0xffc0fffffff;
   const uint64_t r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
   const uint64_t r2 = ((t1 >> 24)) & 0x00ffffffc0f;

   // Store r^1
   X[R_BASE + 0] = r0;
   X[R_BASE + 1] = r1;
   X[R_BASE + 2] = r2;

   poly1305_extend_powers(X, 2);
}

// Process a single block: h = (h + m) * r mod p
BOTAN_FORCE_INLINE void poly1305_block_single(uint64_t& h0,
                                              uint64_t& h1,
                                              uint64_t& h2,
                                              uint64_t r0,
                                              uint64_t r1,
                                              uint64_t r2,
                                              uint64_t s1,
                                              uint64_t s2,
                                              const uint8_t* m,
                                              uint64_t hibit) {
   constexpr uint64_t M44 = 0xFFFFFFFFFFF;
   constexpr uint64_t M42 = 0x3FFFFFFFFFF;

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
   typedef donna128 uint128_t;
#endif

   const uint64_t t0 = load_le<uint64_t>(m, 0);
   const uint64_t t1 = load_le<uint64_t>(m, 1);

   h0 += (t0 & M44);
   h1 += ((t0 >> 44) | (t1 << 20)) & M44;
   h2 += ((t1 >> 24) & M42) | hibit;

   const uint128_t d0 = uint128_t(h0) * r0 + uint128_t(h1) * s2 + uint128_t(h2) * s1;
   const uint64_t c0 = carry_shift(d0, 44);

   const uint128_t d1 = uint128_t(h0) * r1 + uint128_t(h1) * r0 + uint128_t(h2) * s2 + c0;
   const uint64_t c1 = carry_shift(d1, 44);

   const uint128_t d2 = uint128_t(h0) * r2 + uint128_t(h1) * r1 + uint128_t(h2) * r0 + c1;
   const uint64_t c2 = carry_shift(d2, 42);

   h0 = (d0 & M44) + c2 * 5;
   h1 = (d1 & M44) + (h0 >> 44);
   h0 &= M44;
   h2 = d2 & M42;
}

// Process two blocks in parallel: h = ((h + m0) * r + m1) * r = (h + m0) * r^2 + m1 * r
// The multiplications by r^2 and r are independent, enabling ILP
BOTAN_FORCE_INLINE void poly1305_block_pair(uint64_t& h0,
                                            uint64_t& h1,
                                            uint64_t& h2,
                                            uint64_t r0,
                                            uint64_t r1,
                                            uint64_t r2,
                                            uint64_t s1,
                                            uint64_t s2,
                                            uint64_t rr0,
                                            uint64_t rr1,
                                            uint64_t rr2,
                                            uint64_t ss1,
                                            uint64_t ss2,
                                            const uint8_t* m,
                                            uint64_t hibit) {
   constexpr uint64_t M44 = 0xFFFFFFFFFFF;
   constexpr uint64_t M42 = 0x3FFFFFFFFFF;

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
   typedef donna128 uint128_t;
#endif

   // Load first block (will be multiplied by r^2)
   const uint64_t m0_t0 = load_le<uint64_t>(m, 0);
   const uint64_t m0_t1 = load_le<uint64_t>(m, 1);

   // Load second block (will be multiplied by r)
   const uint64_t m1_t0 = load_le<uint64_t>(m + 16, 0);
   const uint64_t m1_t1 = load_le<uint64_t>(m + 16, 1);

   // Add first block to h
   h0 += (m0_t0 & M44);
   h1 += ((m0_t0 >> 44) | (m0_t1 << 20)) & M44;
   h2 += ((m0_t1 >> 24) & M42) | hibit;

   // Convert second block to limbs
   const uint64_t b0 = (m1_t0 & M44);
   const uint64_t b1 = ((m1_t0 >> 44) | (m1_t1 << 20)) & M44;
   const uint64_t b2 = ((m1_t1 >> 24) & M42) | hibit;

   // Compute (h + m0) * r^2 + m1 * r
   const uint128_t d0 = uint128_t(h0) * rr0 + uint128_t(h1) * ss2 + uint128_t(h2) * ss1 + uint128_t(b0) * r0 +
                        uint128_t(b1) * s2 + uint128_t(b2) * s1;
   const uint64_t c0 = carry_shift(d0, 44);

   const uint128_t d1 = uint128_t(h0) * rr1 + uint128_t(h1) * rr0 + uint128_t(h2) * ss2 + uint128_t(b0) * r1 +
                        uint128_t(b1) * r0 + uint128_t(b2) * s2 + c0;
   const uint64_t c1 = carry_shift(d1, 44);

   const uint128_t d2 = uint128_t(h0) * rr2 + uint128_t(h1) * rr1 + uint128_t(h2) * rr0 + uint128_t(b0) * r2 +
                        uint128_t(b1) * r1 + uint128_t(b2) * r0 + c1;
   const uint64_t c2 = carry_shift(d2, 42);

   h0 = (d0 & M44) + c2 * 5;
   h1 = (d1 & M44) + (h0 >> 44);
   h0 &= M44;
   h2 = d2 & M42;
}

void poly1305_blocks(secure_vector<uint64_t>& X, const uint8_t* m, size_t blocks, bool is_final = false) {
   const uint64_t hibit = is_final ? 0 : (static_cast<uint64_t>(1) << 40);

   // Load r (at R_BASE + 0)
   const uint64_t r0 = X[R_BASE + 0];
   const uint64_t r1 = X[R_BASE + 1];
   const uint64_t r2 = X[R_BASE + 2];
   const uint64_t s1 = r1 * 20;
   const uint64_t s2 = r2 * 20;

   // Load r^2 (at R_BASE + 3)
   const uint64_t rr0 = X[R_BASE + 3];
   const uint64_t rr1 = X[R_BASE + 4];
   const uint64_t rr2 = X[R_BASE + 5];

   // Precompute
   const uint64_t ss1 = rr1 * 20;
   const uint64_t ss2 = rr2 * 20;

   // Load accumulator
   uint64_t h0 = X[H_BASE + 0];
   uint64_t h1 = X[H_BASE + 1];
   uint64_t h2 = X[H_BASE + 2];

   while(blocks >= 2) {
      poly1305_block_pair(h0, h1, h2, r0, r1, r2, s1, s2, rr0, rr1, rr2, ss1, ss2, m, hibit);
      m += 32;
      blocks -= 2;
   }

   // Final block?
   if(blocks > 0) {
      poly1305_block_single(h0, h1, h2, r0, r1, r2, s1, s2, m, hibit);
   }

   // Store accumulator
   X[H_BASE + 0] = h0;
   X[H_BASE + 1] = h1;
   X[H_BASE + 2] = h2;
}

void poly1305_finish(secure_vector<uint64_t>& X, uint8_t mac[16]) {
   constexpr uint64_t M44 = 0xFFFFFFFFFFF;
   constexpr uint64_t M42 = 0x3FFFFFFFFFF;

   /* fully carry h */
   uint64_t h0 = X[H_BASE + 0];
   uint64_t h1 = X[H_BASE + 1];
   uint64_t h2 = X[H_BASE + 2];

   uint64_t c = (h1 >> 44);
   h1 &= M44;
   h2 += c;
   c = (h2 >> 42);
   h2 &= M42;
   h0 += c * 5;
   c = (h0 >> 44);
   h0 &= M44;
   h1 += c;
   c = (h1 >> 44);
   h1 &= M44;
   h2 += c;
   c = (h2 >> 42);
   h2 &= M42;
   h0 += c * 5;
   c = (h0 >> 44);
   h0 &= M44;
   h1 += c;

   /* compute h + -p */
   uint64_t g0 = h0 + 5;
   c = (g0 >> 44);
   g0 &= M44;
   uint64_t g1 = h1 + c;
   c = (g1 >> 44);
   g1 &= M44;
   const uint64_t g2 = h2 + c - (static_cast<uint64_t>(1) << 42);

   /* select h if h < p, or h + -p if h >= p */
   const auto c_mask = CT::Mask<uint64_t>::expand(c);
   h0 = c_mask.select(g0, h0);
   h1 = c_mask.select(g1, h1);
   h2 = c_mask.select(g2, h2);

   /* h = (h + pad) */
   const uint64_t t0 = X[PAD_BASE + 0];
   const uint64_t t1 = X[PAD_BASE + 1];

   h0 += ((t0)&M44);
   c = (h0 >> 44);
   h0 &= M44;
   h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c;
   c = (h1 >> 44);
   h1 &= M44;
   h2 += (((t1 >> 24)) & M42) + c;
   h2 &= M42;

   /* mac = h % (2^128) */
   h0 = ((h0) | (h1 << 44));
   h1 = ((h1 >> 20) | (h2 << 24));

   store_le(mac, h0, h1);

   /* zero out the state */
   clear_mem(X.data(), X.size());
}

}  // namespace

void Poly1305::clear() {
   zap(m_poly);
   m_buffer.clear();
}

bool Poly1305::has_keying_material() const {
   // Minimum size: pad(2) + accum(3) + r(3) + r^2(3) = 11
   return m_poly.size() >= 11;
}

void Poly1305::key_schedule(std::span<const uint8_t> key) {
   m_buffer.clear();

   poly1305_init(m_poly, key.data());
}

std::string Poly1305::provider() const {
#if defined(BOTAN_HAS_POLY1305_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_POLY1305_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2)) {
      return *feat;
   }
#endif

   return "base";
}

void Poly1305::add_data(std::span<const uint8_t> input) {
   assert_key_material_set();

   BufferSlicer in(input);

   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         poly1305_blocks(m_poly, one_block->data(), 1);
      }

      if(m_buffer.in_alignment()) {
         const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
         if(full_blocks > 0) {
            const uint8_t* data_ptr = aligned_data.data();
            size_t blocks_remaining = full_blocks;

#if defined(BOTAN_HAS_POLY1305_AVX512)
            if(blocks_remaining >= 8 * 3 && CPUID::has(CPUID::Feature::AVX512)) {
               // Lazily compute r^3 through r^8 on first AVX512 use
               poly1305_extend_powers(m_poly, 8);
               const size_t processed = poly1305_avx512_blocks(m_poly, data_ptr, blocks_remaining);
               data_ptr += processed * 16;
               blocks_remaining -= processed;
            }
#endif

#if defined(BOTAN_HAS_POLY1305_AVX2)
            if(blocks_remaining >= 4 * 6 && CPUID::has(CPUID::Feature::AVX2)) {
               // Lazily compute r^3 and r^4 on first AVX2 use
               poly1305_extend_powers(m_poly, 4);
               const size_t processed = poly1305_avx2_blocks(m_poly, data_ptr, blocks_remaining);
               data_ptr += processed * 16;
               blocks_remaining -= processed;
            }
#endif

            if(blocks_remaining > 0) {
               poly1305_blocks(m_poly, data_ptr, blocks_remaining);
            }
         }
      }
   }
}

void Poly1305::final_result(std::span<uint8_t> out) {
   assert_key_material_set();

   if(!m_buffer.in_alignment()) {
      const uint8_t final_byte = 0x01;
      m_buffer.append({&final_byte, 1});
      m_buffer.fill_up_with_zeros();
      poly1305_blocks(m_poly, m_buffer.consume().data(), 1, true);
   }

   poly1305_finish(m_poly, out.data());

   m_poly.clear();
   m_buffer.clear();
}

}  // namespace Botan
