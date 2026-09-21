/*
 * (C) 2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_avx2.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/kyber_polynomial.h>
#include <array>
#include <immintrin.h>

namespace Botan::Kyber_AVX2 {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

/**
 * SIMD type of 16 signed 16-bit elements
 */
class SIMD_16x16 final {
   public:
      using native_type = __m256i;

      SIMD_16x16(const SIMD_16x16&) = default;
      SIMD_16x16& operator=(const SIMD_16x16&) = default;
      SIMD_16x16(SIMD_16x16&&) = default;
      SIMD_16x16& operator=(SIMD_16x16&&) = default;
      ~SIMD_16x16() = default;

      BOTAN_FN_ISA_AVX2 explicit SIMD_16x16(native_type x) : m_simd(x) {}

      static BOTAN_FN_ISA_AVX2 SIMD_16x16 splat(int16_t v) { return SIMD_16x16(_mm256_set1_epi16(v)); }

      static BOTAN_FN_ISA_AVX2 SIMD_16x16 load(const int16_t in[]) {
         return SIMD_16x16(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(in)));
      }

      BOTAN_FN_ISA_AVX2 void store(int16_t out[]) const {
         _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), m_simd);
      }

      BOTAN_FN_ISA_AVX2 SIMD_16x16 operator+(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_add_epi16(m_simd, o.m_simd));
      }

      BOTAN_FN_ISA_AVX2 SIMD_16x16 operator-(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_sub_epi16(m_simd, o.m_simd));
      }

      /// The low 16 bits of the lane products
      BOTAN_FN_ISA_AVX2 SIMD_16x16 mul_lo(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_mullo_epi16(m_simd, o.m_simd));
      }

      /// The high 16 bits of the signed lane products
      BOTAN_FN_ISA_AVX2 SIMD_16x16 mul_hi(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_mulhi_epi16(m_simd, o.m_simd));
      }

      /// Arithmetic right shift of each lane
      template <int SHIFT>
      BOTAN_FN_ISA_AVX2 SIMD_16x16 sra() const {
         return SIMD_16x16(_mm256_srai_epi16(m_simd, SHIFT));
      }

      /// Lane i is taken from other if bit i of MASK is set
      template <int MASK>
      BOTAN_FN_ISA_AVX2 SIMD_16x16 blend(const SIMD_16x16& other) const {
         return SIMD_16x16(_mm256_blend_epi16(m_simd, other.m_simd, MASK));
      }

      /// Permutes the 32-bit words within each 128-bit half
      template <int CTRL>
      BOTAN_FN_ISA_AVX2 SIMD_16x16 shuffle_32() const {
         return SIMD_16x16(_mm256_shuffle_epi32(m_simd, CTRL));
      }

      /// Permutes the bytes within each 128-bit half using the indexes in tbl
      BOTAN_FN_ISA_AVX2 SIMD_16x16 byte_shuffle(const SIMD_16x16& tbl) const {
         return SIMD_16x16(_mm256_shuffle_epi8(m_simd, tbl.m_simd));
      }

      /// Swaps the two 16-bit halves of each 32-bit lane
      BOTAN_FN_ISA_AVX2 SIMD_16x16 swap_16_halves() const {
         // clang-format off
         const SIMD_16x16 tbl(
            _mm256_setr_epi8(
               2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
               2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13));
         // clang-format on

         return byte_shuffle(tbl);
      }

      /// The low 128-bit halves of a and b
      static BOTAN_FN_ISA_AVX2 SIMD_16x16 concat_lo128(const SIMD_16x16& a, const SIMD_16x16& b) {
         return SIMD_16x16(_mm256_permute2x128_si256(a.m_simd, b.m_simd, 0x20));
      }

      /// The high 128-bit halves of a and b
      static BOTAN_FN_ISA_AVX2 SIMD_16x16 concat_hi128(const SIMD_16x16& a, const SIMD_16x16& b) {
         return SIMD_16x16(_mm256_permute2x128_si256(a.m_simd, b.m_simd, 0x31));
      }

      /// Interleaves the low 64-bit words of each 128-bit half of a and b
      static BOTAN_FN_ISA_AVX2 SIMD_16x16 interleave_lo64(const SIMD_16x16& a, const SIMD_16x16& b) {
         return SIMD_16x16(_mm256_unpacklo_epi64(a.m_simd, b.m_simd));
      }

      /// Interleaves the high 64-bit words of each 128-bit half of a and b
      static BOTAN_FN_ISA_AVX2 SIMD_16x16 interleave_hi64(const SIMD_16x16& a, const SIMD_16x16& b) {
         return SIMD_16x16(_mm256_unpackhi_epi64(a.m_simd, b.m_simd));
      }

   private:
      native_type m_simd;
};

// NOLINTEND(portability-simd-intrinsics)

/// A zeta together with zeta * q^-1 mod 2^16, as used by fqmul_const
struct Zeta {
      SIMD_16x16 z;
      SIMD_16x16 zq;
};

using Lanes = std::array<int16_t, 16>;

/**
 * The precomputed zetas in the lane orders the kernels consume them in.
 *
 * The layers with butterfly distance 8, 4 and 2 operate on each block of 32
 * coefficients held in two registers, regrouped so that every lane pairs up
 * with the lane of the other register. The forward and inverse tables hold
 * the zetas of those layers in that lane order.
 *
 * The basemul zetas are in the even lanes, the odd lanes are unused.
 */
class Tables final {
   public:
      static consteval Tables create() {
         // z * q^-1 mod 2^16, the second multiplier of a Montgomery multiplication by z
         const auto times_qinv = [](int16_t z) -> int16_t {
            return static_cast<int16_t>(static_cast<int32_t>(z) * KyberPolyTraits::q_inverse());
         };

         // The scalar Montgomery reduction
         const auto mont_reduce = [](int32_t a) -> int16_t {
            const int16_t u = static_cast<int16_t>(static_cast<int16_t>(a) * KyberPolyTraits::q_inverse());
            const int32_t t = a - static_cast<int32_t>(u) * KyberConstants::Q;
            return static_cast<int16_t>(t >> 16);
         };

         Tables t;
         const auto& zetas = KyberPolyTraits::zeta_table();

         for(size_t i = 0; i < 128; ++i) {
            t.m_z[i] = zetas[i];
            t.m_zq[i] = times_qinv(zetas[i]);
         }

         for(size_t blk = 0; blk < 8; ++blk) {
            for(size_t l = 0; l < 16; ++l) {
               // Lanes 0..7 hold coefficients 0..7 of the block, lanes 8..15 hold 16..23
               const size_t g8 = l / 8;
               // Lanes 0..3, 4..7, 8..11, 12..15 hold the first half of each group of 8
               const size_t g4 = l / 4;
               // Lane pairs hold the first half of the groups of 4, in this order
               constexpr std::array<size_t, 8> g2_order = {0, 2, 1, 3, 4, 6, 5, 7};
               const size_t g2 = g2_order[l / 2];

               t.m_f8[blk][l] = zetas[16 + 2 * blk + g8];
               t.m_f4[blk][l] = zetas[32 + 4 * blk + g4];
               t.m_f2[blk][l] = zetas[64 + 8 * blk + g2];
               t.m_i8[blk][l] = zetas[31 - (2 * blk + g8)];
               t.m_i4[blk][l] = zetas[63 - (4 * blk + g4)];
               t.m_i2[blk][l] = zetas[127 - (8 * blk + g2)];

               t.m_f8q[blk][l] = times_qinv(t.m_f8[blk][l]);
               t.m_f4q[blk][l] = times_qinv(t.m_f4[blk][l]);
               t.m_f2q[blk][l] = times_qinv(t.m_f2[blk][l]);
               t.m_i8q[blk][l] = times_qinv(t.m_i8[blk][l]);
               t.m_i4q[blk][l] = times_qinv(t.m_i4[blk][l]);
               t.m_i2q[blk][l] = times_qinv(t.m_i2[blk][l]);
            }
         }

         for(size_t v = 0; v < 16; ++v) {
            for(size_t l = 0; l < 16; l += 2) {
               const size_t pair = 8 * v + l / 2;
               const int16_t z = zetas[64 + pair / 2];
               t.m_b[v][l] = (pair % 2 == 0) ? z : static_cast<int16_t>(-z);
               t.m_bq[v][l] = times_qinv(t.m_b[v][l]);
            }
         }

         // The final scaling of the inverse NTT, folded into its last layer
         t.m_fm = KyberPolyTraits::inverse_ntt_scale();
         t.m_fmq = times_qinv(t.m_fm);
         t.m_fz = mont_reduce(static_cast<int32_t>(zetas[1]) * t.m_fm);
         t.m_fzq = times_qinv(t.m_fz);

         return t;
      }

      /// The zeta of butterfly k, for the layers with distance 16 and above
      BOTAN_FN_ISA_AVX2 Zeta zeta(size_t k) const { return {SIMD_16x16::splat(m_z[k]), SIMD_16x16::splat(m_zq[k])}; }

      BOTAN_FN_ISA_AVX2 Zeta forward_8(size_t blk) const { return lanes(m_f8[blk], m_f8q[blk]); }

      BOTAN_FN_ISA_AVX2 Zeta forward_4(size_t blk) const { return lanes(m_f4[blk], m_f4q[blk]); }

      BOTAN_FN_ISA_AVX2 Zeta forward_2(size_t blk) const { return lanes(m_f2[blk], m_f2q[blk]); }

      BOTAN_FN_ISA_AVX2 Zeta inverse_8(size_t blk) const { return lanes(m_i8[blk], m_i8q[blk]); }

      BOTAN_FN_ISA_AVX2 Zeta inverse_4(size_t blk) const { return lanes(m_i4[blk], m_i4q[blk]); }

      BOTAN_FN_ISA_AVX2 Zeta inverse_2(size_t blk) const { return lanes(m_i2[blk], m_i2q[blk]); }

      /// The basemul zetas of register v of the polynomial
      BOTAN_FN_ISA_AVX2 Zeta basemul(size_t v) const { return lanes(m_b[v], m_bq[v]); }

      /// The scaling factor of the inverse NTT
      BOTAN_FN_ISA_AVX2 Zeta final_scale() const { return {SIMD_16x16::splat(m_fm), SIMD_16x16::splat(m_fmq)}; }

      /// The zeta of the last inverse NTT layer, with the scaling factor folded in
      BOTAN_FN_ISA_AVX2 Zeta final_zeta() const { return {SIMD_16x16::splat(m_fz), SIMD_16x16::splat(m_fzq)}; }

      // This needs to be public due to a MSVC bug, use ::create
      constexpr Tables() = default;

   private:
      static BOTAN_FN_ISA_AVX2 Zeta lanes(const Lanes& z, const Lanes& zq) {
         return {SIMD_16x16::load(z.data()), SIMD_16x16::load(zq.data())};
      }

      std::array<int16_t, 128> m_z{};
      std::array<int16_t, 128> m_zq{};
      std::array<Lanes, 8> m_f8{};
      std::array<Lanes, 8> m_f8q{};
      std::array<Lanes, 8> m_f4{};
      std::array<Lanes, 8> m_f4q{};
      std::array<Lanes, 8> m_f2{};
      std::array<Lanes, 8> m_f2q{};
      std::array<Lanes, 8> m_i8{};
      std::array<Lanes, 8> m_i8q{};
      std::array<Lanes, 8> m_i4{};
      std::array<Lanes, 8> m_i4q{};
      std::array<Lanes, 8> m_i2{};
      std::array<Lanes, 8> m_i2q{};
      std::array<Lanes, 16> m_b{};
      std::array<Lanes, 16> m_bq{};
      int16_t m_fm = 0;
      int16_t m_fmq = 0;
      int16_t m_fz = 0;
      int16_t m_fzq = 0;
};

constexpr Tables TABLES = Tables::create();

/// Montgomery multiplication by a constant
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE SIMD_16x16 fqmul_const(SIMD_16x16 a, const Zeta& zeta, SIMD_16x16 q) {
   const auto hi = a.mul_hi(zeta.z);
   const auto u = a.mul_lo(zeta.zq);
   return hi - u.mul_hi(q);
}

/// Montgomery multiplication of two variables
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE SIMD_16x16 fqmul(SIMD_16x16 a, SIMD_16x16 b, SIMD_16x16 qinv, SIMD_16x16 q) {
   const auto hi = a.mul_hi(b);
   const auto u = a.mul_lo(b).mul_lo(qinv);
   return hi - u.mul_hi(q);
}

BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE SIMD_16x16 barrett(SIMD_16x16 a, SIMD_16x16 v, SIMD_16x16 q) {
   const auto t = a.mul_hi(v).sra<10>();
   return a - t.mul_lo(q);
}

BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void ct_butterfly(SIMD_16x16& a, SIMD_16x16& b, const Zeta& zeta, SIMD_16x16 q) {
   const auto t = fqmul_const(b, zeta, q);
   b = a - t;
   a = a + t;
}

/// Gentleman-Sande butterfly; the sum is left unreduced
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void gs_butterfly(SIMD_16x16& a, SIMD_16x16& b, const Zeta& zeta, SIMD_16x16 q) {
   const auto t = b - a;
   a = a + b;
   b = fqmul_const(t, zeta, q);
}

/*
 * Regroupings of a block of 32 coefficients between the register layouts of
 * consecutive layers. Coefficient i of the block is in register a (i < 16)
 * or b (i >= 16) at the distance 16 layer, and each layer below halves the
 * distance between the lanes that pair up. Each helper converts in both
 * directions unless noted.
 */

/// Distance 16 <-> 8: a = {0..7, 16..23}, b = {8..15, 24..31}
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void swap_halves(SIMD_16x16& a, SIMD_16x16& b) {
   const auto x = SIMD_16x16::concat_lo128(a, b);
   const auto y = SIMD_16x16::concat_hi128(a, b);
   a = x;
   b = y;
}

/// Distance 8 <-> 4: a = {0..3, 8..11, 16..19, 24..27}, b = {4..7, ...}
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void interleave64(SIMD_16x16& a, SIMD_16x16& b) {
   const auto x = SIMD_16x16::interleave_lo64(a, b);
   const auto y = SIMD_16x16::interleave_hi64(a, b);
   a = x;
   b = y;
}

/// Distance 4 -> 2: a = {0,1, 8,9, 4,5, 12,13, 16,17, 24,25, 20,21, 28,29}, b = a + 2
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void distance_4_to_2(SIMD_16x16& a, SIMD_16x16& b) {
   a = a.shuffle_32<0xD8>();
   b = b.shuffle_32<0xD8>();
   interleave64(a, b);
}

/// Distance 2 -> 4
BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void distance_2_to_4(SIMD_16x16& a, SIMD_16x16& b) {
   interleave64(a, b);
   a = a.shuffle_32<0xD8>();
   b = b.shuffle_32<0xD8>();
}

}  // namespace

/*
 * Same structure as KyberPolyTraits::ntt: no reduction between the layers
 * (the coefficients stay below 8q in magnitude), Barrett at the end.
 */
BOTAN_FN_ISA_AVX2 void ntt(std::span<int16_t, 256> p) {
   int16_t* c = p.data();
   const auto q = SIMD_16x16::splat(KyberConstants::Q);

   size_t k = 1;
   for(size_t len = 128; len >= 16; len >>= 1) {
      for(size_t start = 0; start < 256; start += 2 * len, ++k) {
         const Zeta zeta = TABLES.zeta(k);
         for(size_t j = start; j < start + len; j += 16) {
            auto a = SIMD_16x16::load(c + j);
            auto b = SIMD_16x16::load(c + j + len);
            ct_butterfly(a, b, zeta, q);
            a.store(c + j);
            b.store(c + j + len);
         }
      }
   }

   const auto v = SIMD_16x16::splat(KyberPolyTraits::BARRETT_V);
   for(size_t blk = 0; blk < 8; ++blk) {
      int16_t* cb = c + 32 * blk;
      auto a = SIMD_16x16::load(cb);
      auto b = SIMD_16x16::load(cb + 16);

      swap_halves(a, b);
      ct_butterfly(a, b, TABLES.forward_8(blk), q);
      interleave64(a, b);
      ct_butterfly(a, b, TABLES.forward_4(blk), q);
      distance_4_to_2(a, b);
      ct_butterfly(a, b, TABLES.forward_2(blk), q);
      distance_2_to_4(a, b);
      interleave64(a, b);
      swap_halves(a, b);

      barrett(a, v, q).store(cb);
      barrett(b, v, q).store(cb + 16);
   }
}

/*
 * Unlike KyberPolyTraits::inverse_ntt, the sums are only reduced after every
 * second layer. Starting from coefficients in (-q, q), a layer at most
 * doubles the magnitude of its sums, while its differences are reduced by the
 * Montgomery multiplication. So the sums reach 4q before each reduction and
 * the differences fed to the multiplication stay below 4q, both well within
 * the 16-bit lanes. The final scaling by f * R is folded into the last layer.
 */
BOTAN_FN_ISA_AVX2 void inverse_ntt(std::span<int16_t, 256> p) {
   int16_t* c = p.data();
   const auto q = SIMD_16x16::splat(KyberConstants::Q);
   const auto v = SIMD_16x16::splat(KyberPolyTraits::BARRETT_V);

   for(size_t blk = 0; blk < 8; ++blk) {
      int16_t* cb = c + 32 * blk;
      auto a = SIMD_16x16::load(cb);
      auto b = SIMD_16x16::load(cb + 16);

      swap_halves(a, b);
      interleave64(a, b);
      distance_4_to_2(a, b);
      gs_butterfly(a, b, TABLES.inverse_2(blk), q);
      distance_2_to_4(a, b);
      gs_butterfly(a, b, TABLES.inverse_4(blk), q);
      a = barrett(a, v, q);
      interleave64(a, b);
      gs_butterfly(a, b, TABLES.inverse_8(blk), q);
      swap_halves(a, b);

      a.store(cb);
      b.store(cb + 16);
   }

   const Zeta scale = TABLES.final_scale();

   size_t k = 15;
   for(size_t len = 16; len <= 128; len <<= 1) {
      const bool reduce = (len == 16 || len == 64);
      const bool last = (len == 128);

      for(size_t start = 0; start < 256; start += 2 * len, --k) {
         const Zeta zeta = last ? TABLES.final_zeta() : TABLES.zeta(k);
         for(size_t j = start; j < start + len; j += 16) {
            auto a = SIMD_16x16::load(c + j);
            auto b = SIMD_16x16::load(c + j + len);
            gs_butterfly(a, b, zeta, q);
            if(reduce) {
               a = barrett(a, v, q);
            }
            if(last) {
               a = fqmul_const(a, scale, q);
            }
            a.store(c + j);
            b.store(c + j + len);
         }
      }
   }
}

/*
 * Works on the interleaved (a0, a1) pairs directly: the products of matching
 * and of swapped lanes give a0*b0, a1*b1 and a0*b1, a1*b0, from which the two
 * result coefficients are assembled with one more multiplication by zeta.
 */
BOTAN_FN_ISA_AVX2 void poly_pointwise_montgomery(std::span<int16_t, 256> result,
                                                 std::span<const int16_t, 256> lhs,
                                                 std::span<const int16_t, 256> rhs) {
   const auto q = SIMD_16x16::splat(KyberConstants::Q);
   const auto qinv = SIMD_16x16::splat(KyberPolyTraits::q_inverse());

   for(size_t i = 0; i < 16; ++i) {
      const auto a = SIMD_16x16::load(lhs.data() + 16 * i);
      const auto b = SIMD_16x16::load(rhs.data() + 16 * i);

      const auto ab = fqmul(a, b, qinv, q);
      const auto ab_swapped = fqmul(a, b.swap_16_halves(), qinv, q);

      const auto zeta_a1b1 = fqmul_const(ab.swap_16_halves(), TABLES.basemul(i), q);

      const auto r0 = ab + zeta_a1b1;
      const auto r1 = ab_swapped + ab_swapped.swap_16_halves();

      r0.blend<0xAA>(r1).store(result.data() + 16 * i);
   }
}

}  // namespace Botan::Kyber_AVX2
