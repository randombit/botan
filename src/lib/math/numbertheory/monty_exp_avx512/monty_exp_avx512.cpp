/*
* Montgomery exponentiation using AVX-512 IFMA
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/monty_exp_avx512.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/mul128.h>
#include <botan/internal/simd_8x64.h>
#include <array>

namespace Botan {

namespace {

static_assert(std::same_as<word, uint64_t>);

constexpr size_t DigitBits = 52;
constexpr uint64_t DigitMask = (static_cast<uint64_t>(1) << DigitBits) - 1;

/*
* Number of radix 2^52 digits used for a modulus of p_bits
*
* The two extra bits ensure 4*p < 2^(52*k), so the Montgomery products of
* values in [0, 2p) are again in [0, 2p) without any conditional subtraction.
*/
constexpr size_t ifma_digits(size_t p_bits) {
   return (p_bits + 2 + DigitBits - 1) / DigitBits;
}

/*
* Low 52 bits of a*b
*
* The product is kept opaque to the optimizer; otherwise the SLP vectorizer
* folds pairs of these into a high latency vector multiply, which puts the
* vector unit on the critical path the scalar chain exists to avoid.
*/
inline uint64_t lo52(uint64_t a, uint64_t b) {
   return CT::value_barrier(a * b) & DigitMask;
}

/*
* Bits 52..103 of a*b, for a and b < 2^52
*
* Pre-shifting a by 12 places exactly these bits in the upper word
*/
inline uint64_t hi52(uint64_t a, uint64_t b) {
   uint64_t lo = 0;
   uint64_t hi = 0;
   mul64x64_128(a << (64 - DigitBits), b, &lo, &hi);
   return hi;
}

template <size_t N>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void shift_lanes_down(std::array<SIMD_8x64, N>& v) {
   for(size_t i = 0; i + 1 < N; ++i) {
      v[i] = SIMD_8x64::alignr<1>(v[i + 1], v[i]);
   }
   v[N - 1] = SIMD_8x64::alignr<1>(SIMD_8x64(), v[N - 1]);
}

template <size_t N>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void shift_lanes_up(std::array<SIMD_8x64, N>& v) {
   for(size_t i = N - 1; i > 0; --i) {
      v[i] = SIMD_8x64::alignr<7>(v[i], v[i - 1]);
   }
   v[0] = SIMD_8x64::alignr<7>(v[0], SIMD_8x64());
}

/*
* Convert lanes holding values below 2^60 into proper 52 bit digits
*/
template <size_t N>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void normalize_digits(std::array<SIMD_8x64, N>& r) {
   static_assert(N <= 16, "Lane masks must fit in two words");

   const auto mask = SIMD_8x64::splat(DigitMask);
   const auto one = SIMD_8x64::splat(1);

   // Pass the excess above 52 bits one lane up; afterwards all lanes are below 2^53
   auto carry = r;
   for(size_t i = 0; i != N; ++i) {
      carry[i] = carry[i].template shr<DigitBits>();
      r[i] &= mask;
   }
   shift_lanes_up(carry);
   for(size_t i = 0; i != N; ++i) {
      r[i] += carry[i];
   }

   /*
   * Now a lane >= 2^52 generates a carry and a lane == 2^52-1 propagates one.
   * Integer addition on the lane masks resolves the entire carry chain at once:
   * carry_in = ((gen << 1) + prop) ^ prop, computed here on two words.
   */
   std::array<uint64_t, 2> gen = {};
   std::array<uint64_t, 2> prop = {};
   for(size_t i = 0; i != N; ++i) {
      gen[i / 8] |= static_cast<uint64_t>(r[i].lanes_gt(mask)) << (8 * (i % 8));
      prop[i / 8] |= static_cast<uint64_t>(r[i].lanes_eq(mask)) << (8 * (i % 8));
   }

   uint64_t c = 0;
   const uint64_t sum0 = word_add(gen[0] << 1, prop[0], &c);
   const uint64_t sum1 = word_add((gen[1] << 1) | (gen[0] >> 63), prop[1], &c);
   const std::array<uint64_t, 2> carry_in = {sum0 ^ prop[0], sum1 ^ prop[1]};

   for(size_t i = 0; i != N; ++i) {
      const auto lanes = static_cast<uint8_t>(carry_in[i / 8] >> (8 * (i % 8)));
      r[i] = SIMD_8x64::masked_add(lanes, r[i], one) & mask;
   }
}

/*
* One round of operand scanning Montgomery multiplication: add a*b_i and p*y_i
* to the accumulators, shifting them down a lane in between. The low halves of
* the products are added before the shift and the high halves after it, which
* puts them in the right lane for free. Using separate accumulators for the
* a*b and p*y products halves the dependency chain.
*
* Only vectors First and up of a take part, and within vector First only the
* lanes selected by a_mask; squaring uses this to skip the lanes below the
* current digit.
*/
template <size_t First, size_t N>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void monty_round(std::array<SIMD_8x64, N>& acc_a,
                                                        std::array<SIMD_8x64, N>& acc_p,
                                                        const std::array<SIMD_8x64, N>& av,
                                                        const std::array<SIMD_8x64, N>& pv,
                                                        const SIMD_8x64& bv,
                                                        const SIMD_8x64& yv,
                                                        uint8_t a_mask) {
   acc_a[First] = acc_a[First].masked_madd52lo(a_mask, av[First], bv);
   for(size_t j = First + 1; j < N; ++j) {
      acc_a[j] = acc_a[j].madd52lo(av[j], bv);
   }
   for(size_t j = 0; j != N; ++j) {
      acc_p[j] = acc_p[j].madd52lo(pv[j], yv);
   }

   shift_lanes_down(acc_a);
   shift_lanes_down(acc_p);

   acc_a[First] = acc_a[First].masked_madd52hi(a_mask, av[First], bv);
   for(size_t j = First + 1; j < N; ++j) {
      acc_a[j] = acc_a[j].madd52hi(av[j], bv);
   }
   for(size_t j = 0; j != N; ++j) {
      acc_p[j] = acc_p[j].madd52hi(pv[j], yv);
   }
}

/*
* Store the final accumulator as normalized digits. The vector lanes never
* received the limb 0 carries; the last one is still missing.
*/
template <size_t N>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void store_digits(std::array<SIMD_8x64, N>& acc,
                                                         uint64_t carry,
                                                         std::span<uint64_t, 8 * N> z) {
   acc[0] = SIMD_8x64::masked_add(0x01, acc[0], SIMD_8x64::splat(carry));

   normalize_digits(acc);

   for(size_t i = 0; i != N; ++i) {
      acc[i].store_le(&z[8 * i]);
   }
}

// Return true if the words encode a value below 2^bits (used in debug assertions)
[[maybe_unused]] bool fits_in_bits(std::span<const word> words, size_t bits) {
   for(size_t i = 0; i != words.size(); ++i) {
      const size_t offset = WordInfo<word>::bits * i;
      if(offset >= bits && words[i] != 0) {
         return false;
      }
      if(offset < bits && offset + WordInfo<word>::bits > bits && (words[i] >> (bits - offset)) != 0) {
         return false;
      }
   }
   return true;
}

/**
* A modulus in radix 2^52 form, with Montgomery multiplication using IFMA
*
* N is the number of 8 lane vectors required to hold the digits
*/
template <size_t N>
class IFMA_Modulus final {
   public:
      static constexpr size_t Lanes = 8 * N;

      using Digits = std::array<uint64_t, Lanes>;

      explicit IFMA_Modulus(const Montgomery_Params& params);

      const Montgomery_Params& params() const { return m_params; }

      /**
      * Montgomery multiplication: z = a*b / 2^(52*k) mod p
      *
      * Inputs and output are in [0, 2p). The output may alias either input.
      */
      void mul(std::span<uint64_t, Lanes> z,
               std::span<const uint64_t, Lanes> a,
               std::span<const uint64_t, Lanes> b) const;

      /**
      * Montgomery squaring: z = a*a / 2^(52*k) mod p
      *
      * Input and output are in [0, 2p). The output may alias the input.
      */
      void sqr(std::span<uint64_t, Lanes> z, std::span<const uint64_t, Lanes> a) const;

      /**
      * Return 1 in the radix 2^52 Montgomery domain
      */
      const Digits& one() const { return m_one; }

      /**
      * Convert a Montgomery_Int into the radix 2^52 Montgomery domain
      */
      Digits from_monty_int(const Montgomery_Int& x) const;

      /**
      * Convert from the radix 2^52 Montgomery domain into a Montgomery_Int
      */
      Montgomery_Int to_monty_int(std::span<const uint64_t, Lanes> x) const;

   private:
      template <size_t First>
      void sqr_rounds(std::array<SIMD_8x64, N>& acc_a,
                      std::array<SIMD_8x64, N>& acc_p,
                      const std::array<SIMD_8x64, N>& av,
                      const std::array<SIMD_8x64, N>& pv,
                      std::span<const uint64_t, Lanes> a,
                      std::span<const uint64_t, 2 * Lanes> diag,
                      uint64_t& s,
                      uint64_t& carry) const;

      // Convert words encoding a value below 2^(52*k) into digits
      Digits to_digits(std::span<const word> words) const;

      Montgomery_Params m_params;
      Digits m_p;
      Digits m_r1;   // R = 2^(64*n) mod p, the Montgomery_Int domain constant
      Digits m_c;    // R'^2/R = 2^(104*k - 64*n) mod p, converting R*x into R'*x
      Digits m_one;  // R' = 2^(52*k) mod p
      uint64_t m_k0;
      size_t m_digits;
};

template <size_t N>
IFMA_Modulus<N>::IFMA_Modulus(const Montgomery_Params& params) :
      m_params(params), m_k0(params.p_dash() & DigitMask), m_digits(ifma_digits(params.p().bits())) {
   BOTAN_ASSERT_NOMSG(m_digits > 1 && m_digits <= Lanes);

   m_p = to_digits(params.p()._as_span());
   m_r1 = to_digits(params.R1()._as_span());

   /*
   * Derive C = 2^(2*rp - r) from R = 2^r or R^2 = 2^(2*r) using the existing
   * Montgomery multiplication, which computes x*y*2^(-r).
   */
   const size_t r = WordInfo<word>::bits * params.p_words();
   const size_t rp = DigitBits * m_digits;

   secure_vector<word> ws;
   if(rp >= r) {
      m_c = to_digits(params.mul(params.R2(), BigInt::power_of_2(2 * (rp - r)), ws)._as_span());
   } else {
      m_c = to_digits(params.mul(params.R1(), BigInt::power_of_2(2 * rp - r), ws)._as_span());
   }

   // R * C / R' = R'
   this->mul(m_one, m_r1, m_c);
}

template <size_t N>
typename IFMA_Modulus<N>::Digits IFMA_Modulus<N>::to_digits(std::span<const word> words) const {
   Digits d = {};
   for(size_t i = 0; i != m_digits; ++i) {
      const size_t bit = DigitBits * i;
      const size_t w = bit / 64;
      const size_t sh = bit % 64;

      uint64_t v = (w < words.size()) ? (words[w] >> sh) : 0;
      if(sh > 64 - DigitBits && w + 1 < words.size()) {
         v |= words[w + 1] << (64 - sh);
      }
      d[i] = v & DigitMask;
   }

   BOTAN_DEBUG_ASSERT(fits_in_bits(words, DigitBits * m_digits));

   return d;
}

template <size_t N>
typename IFMA_Modulus<N>::Digits IFMA_Modulus<N>::from_monty_int(const Montgomery_Int& x) const {
   // x is R*v mod p, multiplying by C converts it to R'*v
   const Digits v = to_digits(x.repr());
   Digits r = {};
   this->mul(r, v, m_c);
   return r;
}

template <size_t N>
Montgomery_Int IFMA_Modulus<N>::to_monty_int(std::span<const uint64_t, Lanes> x) const {
   Digits z = {};
   this->mul(z, x, m_r1);

   // z is now x*R mod p in [0, 2p), as normalized digits
   const size_t n = m_params.p_words();
   secure_vector<word> w(n + 1);
   for(size_t i = 0; i != m_digits; ++i) {
      const size_t bit = DigitBits * i;
      const size_t wi = bit / 64;
      const size_t sh = bit % 64;

      w[wi] |= z[i] << sh;
      if(sh > 64 - DigitBits && wi + 1 < w.size()) {
         w[wi + 1] |= z[i] >> (64 - sh);
      }
   }

   secure_vector<word> r(n);
   bigint_monty_maybe_sub(n, r.data(), w[n], w.data(), m_params.p()._data());
   return Montgomery_Int(m_params, std::span<const word>{r});
}

/*
* Operand scanning Montgomery multiplication in radix 2^52
*
* Each round multiplies the whole of a (and of p) by one digit of b (resp
* the quotient digit y) using IFMA, then shifts the accumulator down a lane.
*
* The lowest lane is where the next quotient digit comes from, and waiting
* for the vector unit to produce it would stall the whole loop. Instead the
* scalar unit tracks the exact value of limb 0 one round ahead, using the
* lane 1 values from the previous round, and the vector lanes never see the
* limb 0 carries at all; the final one is added back at the end.
*/
template <size_t N>
void BOTAN_FN_ISA_AVX512 IFMA_Modulus<N>::mul(std::span<uint64_t, Lanes> z,
                                              std::span<const uint64_t, Lanes> a,
                                              std::span<const uint64_t, Lanes> b) const {
   std::array<SIMD_8x64, N> av;
   std::array<SIMD_8x64, N> pv;
   for(size_t i = 0; i != N; ++i) {
      av[i] = SIMD_8x64::load_le(&a[8 * i]);
      pv[i] = SIMD_8x64::load_le(&m_p[8 * i]);
   }

   /*
   * The contributions of a*b_i to limbs 0 and 1 in each round depend only
   * on b, so they are computed for all rounds up front
   */
   std::array<uint64_t, Lanes> ab0 = {};  // lo52(a0 * b_i)
   std::array<uint64_t, Lanes> ab1 = {};  // hi52(a0 * b_i) + lo52(a1 * b_i)
   {
      const auto a0v = SIMD_8x64::splat(a[0]);
      const auto a1v = SIMD_8x64::splat(a[1]);
      for(size_t i = 0; i != N; ++i) {
         const auto bv = SIMD_8x64::load_le(&b[8 * i]);
         SIMD_8x64().madd52lo(a0v, bv).store_le(&ab0[8 * i]);
         SIMD_8x64().madd52hi(a0v, bv).madd52lo(a1v, bv).store_le(&ab1[8 * i]);
      }
   }

   std::array<SIMD_8x64, N> acc_a;
   std::array<SIMD_8x64, N> acc_p;

   const uint64_t p0 = m_p[0];
   const uint64_t p1 = m_p[1];
   const uint64_t k0 = m_k0;

   uint64_t s = 0;  // exact value of limb 0
   uint64_t carry = 0;

   for(size_t i = 0; i != m_digits; ++i) {
      const uint64_t t = s + ab0[i];
      const uint64_t y = (t * k0) & DigitMask;

      // y was chosen such that t + lo52(p0 * y) is a multiple of 2^52
      carry = (t + DigitMask) >> DigitBits;

      // Everything that lands in limb 1 this round is the next limb 0
      const uint64_t limb1 = (acc_a[0] + acc_p[0]).template extract<1>();
      s = limb1 + carry + hi52(p0, y) + lo52(p1, y) + ab1[i];

      monty_round<0>(acc_a, acc_p, av, pv, SIMD_8x64::splat(b[i]), SIMD_8x64::splat(y), 0xFF);
   }

   for(size_t i = 0; i != N; ++i) {
      acc_a[i] += acc_p[i];
   }

   store_digits(acc_a, carry, z);
}

/*
* Montgomery squaring
*
* Each product a_j*a_i with j != i appears twice in the square, so each round
* only forms the products with j above the current digit i, and the
* accumulator is doubled whenever it is read. That skips entire vectors once
* the digit has passed them. The squares a_i^2 are added separately: their
* low half belongs at position 2i and their high half at position 2i+1.
*/
template <size_t N>
void BOTAN_FN_ISA_AVX512 IFMA_Modulus<N>::sqr(std::span<uint64_t, Lanes> z, std::span<const uint64_t, Lanes> a) const {
   std::array<SIMD_8x64, N> av;
   std::array<SIMD_8x64, N> pv;
   for(size_t i = 0; i != N; ++i) {
      av[i] = SIMD_8x64::load_le(&a[8 * i]);
      pv[i] = SIMD_8x64::load_le(&m_p[8 * i]);
   }

   std::array<uint64_t, 2 * Lanes> diag = {};
   for(size_t i = 0; i != N; ++i) {
      const auto lo = SIMD_8x64().madd52lo(av[i], av[i]);
      const auto hi = SIMD_8x64().madd52hi(av[i], av[i]);
      SIMD_8x64::interleave_lo(lo, hi).store_le(&diag[16 * i]);
      SIMD_8x64::interleave_hi(lo, hi).store_le(&diag[16 * i + 8]);
   }

   std::array<SIMD_8x64, N> acc_a;
   std::array<SIMD_8x64, N> acc_p;

   uint64_t s = diag[0];  // exact value of limb 0
   uint64_t carry = 0;

   this->sqr_rounds<0>(acc_a, acc_p, av, pv, a, diag, s, carry);

   // The positions from k onwards are what remains after the k shifts
   for(size_t i = 0; i != N; ++i) {
      acc_a[i] = acc_a[i] + acc_a[i] + acc_p[i] + SIMD_8x64::load_le(&diag[m_digits + 8 * i]);
   }

   store_digits(acc_a, carry, z);
}

/*
* The rounds for the digits held in vector First, in which the products with
* the lanes below the digit are skipped
*/
template <size_t N>
template <size_t First>
void BOTAN_FN_ISA_AVX512 IFMA_Modulus<N>::sqr_rounds(std::array<SIMD_8x64, N>& acc_a,
                                                     std::array<SIMD_8x64, N>& acc_p,
                                                     const std::array<SIMD_8x64, N>& av,
                                                     const std::array<SIMD_8x64, N>& pv,
                                                     std::span<const uint64_t, Lanes> a,
                                                     std::span<const uint64_t, 2 * Lanes> diag,
                                                     uint64_t& s,
                                                     uint64_t& carry) const {
   const uint64_t p0 = m_p[0];
   const uint64_t p1 = m_p[1];
   const uint64_t k0 = m_k0;

   // The only product below the diagonal landing in limb 1 is a_0*a_1 in round 0
   uint64_t a0a1 = (First == 0) ? 2 * lo52(a[0], a[1]) : 0;

   for(size_t d = 0; d != 8; ++d) {
      const size_t i = 8 * First + d;
      if(i == m_digits) {
         return;
      }

      const uint64_t y = (s * k0) & DigitMask;

      // y was chosen such that s + lo52(p0 * y) is a multiple of 2^52
      carry = (s + DigitMask) >> DigitBits;

      // Everything that lands in limb 1 this round is the next limb 0
      const uint64_t limb1 = (acc_a[0] + acc_a[0] + acc_p[0]).template extract<1>();
      s = limb1 + carry + hi52(p0, y) + lo52(p1, y) + diag[i + 1] + a0a1;
      a0a1 = 0;

      const auto a_mask = static_cast<uint8_t>(0xFF << (d + 1));
      monty_round<First>(acc_a, acc_p, av, pv, SIMD_8x64::splat(a[i]), SIMD_8x64::splat(y), a_mask);
   }

   if constexpr(First + 1 < N) {
      this->sqr_rounds<First + 1>(acc_a, acc_p, av, pv, a, diag, s, carry);
   }
}

template <size_t N>
class Montgomery_Exponentiation_AVX512 final : public Montgomery_Exponentiation_State {
   public:
      static constexpr size_t Lanes = IFMA_Modulus<N>::Lanes;

      using Digits = typename IFMA_Modulus<N>::Digits;

      Montgomery_Exponentiation_AVX512(const Montgomery_Int& g, size_t window_bits, bool const_time) :
            m_monty(g._params()), m_window_bits(window_bits) {
         const size_t window_size = static_cast<size_t>(1) << m_window_bits;

         m_table.resize(window_size * Lanes);

         const Digits g_digits = m_monty.from_monty_int(g);

         copy_mem(entry(0), std::span{m_monty.one()});
         copy_mem(entry(1), std::span{g_digits});

         for(size_t i = 2; i != window_size; ++i) {
            if(i % 2 == 0) {
               m_monty.sqr(entry(i), entry(i / 2));
            } else {
               m_monty.mul(entry(i), entry(1), entry(i - 1));
            }
         }

         if(const_time) {
            CT::poison(m_table);
         }
      }

      Montgomery_Int exponentiation(const BigInt& scalar, size_t max_k_bits) const override {
         BOTAN_ARG_CHECK(scalar.signum() >= 0, "Invalid scalar for Montgomery exponentiation");
         BOTAN_DEBUG_ASSERT(scalar.bits() <= max_k_bits);

         const size_t exp_nibbles = (max_k_bits + m_window_bits - 1) / m_window_bits;

         if(exp_nibbles == 0) {
            return Montgomery_Int::one(m_monty.params());
         }

         Digits x = {};
         Digits e = {};

         ct_lookup(x, scalar.get_substring(m_window_bits * (exp_nibbles - 1), m_window_bits));

         for(size_t i = exp_nibbles - 1; i > 0; --i) {
            for(size_t j = 0; j != m_window_bits; ++j) {
               m_monty.sqr(x, x);
            }
            ct_lookup(e, scalar.get_substring(m_window_bits * (i - 1), m_window_bits));
            m_monty.mul(x, x, e);
         }

         auto r = m_monty.to_monty_int(x);
         CT::unpoison(r);
         return r;
      }

      Montgomery_Int exponentiation_vartime(const BigInt& scalar) const override {
         const size_t exp_nibbles = (scalar.bits() + m_window_bits - 1) / m_window_bits;

         if(exp_nibbles == 0) {
            return Montgomery_Int::one(m_monty.params());
         }

         Digits x = {};
         copy_mem(std::span{x}, entry(scalar.get_substring(m_window_bits * (exp_nibbles - 1), m_window_bits)));

         for(size_t i = exp_nibbles - 1; i > 0; --i) {
            for(size_t j = 0; j != m_window_bits; ++j) {
               m_monty.sqr(x, x);
            }

            const uint32_t nibble = scalar.get_substring(m_window_bits * (i - 1), m_window_bits);
            if(nibble > 0) {
               m_monty.mul(x, x, entry(nibble));
            }
         }

         return m_monty.to_monty_int(x);
      }

   private:
      std::span<uint64_t, Lanes> entry(size_t i) {
         return std::span{m_table}.subspan(i * Lanes).template first<Lanes>();
      }

      std::span<const uint64_t, Lanes> entry(size_t i) const {
         return std::span{m_table}.subspan(i * Lanes).template first<Lanes>();
      }

      void BOTAN_FN_ISA_AVX512 ct_lookup(Digits& out, size_t idx) const {
         std::array<SIMD_8x64, N> acc;

         const size_t window_size = static_cast<size_t>(1) << m_window_bits;

         for(size_t i = 0; i != window_size; ++i) {
            const auto mask = SIMD_8x64::splat(CT::Mask<uint64_t>::is_equal(idx, i).value());
            const auto e = entry(i);
            for(size_t j = 0; j != N; ++j) {
               acc[j] = SIMD_8x64::choose(mask, SIMD_8x64::load_le(&e[8 * j]), acc[j]);
            }
         }

         for(size_t j = 0; j != N; ++j) {
            acc[j].store_le(&out[8 * j]);
         }
      }

      IFMA_Modulus<N> m_monty;
      secure_vector<uint64_t> m_table;
      size_t m_window_bits;
};

template <size_t N>
std::unique_ptr<Montgomery_Exponentiation_State> make_monty_exp(const Montgomery_Int& g,
                                                                size_t window_bits,
                                                                bool const_time) {
   return std::make_unique<Montgomery_Exponentiation_AVX512<N>>(g, window_bits, const_time);
}

}  // namespace

std::unique_ptr<Montgomery_Exponentiation_State> make_monty_exp_avx512(const Montgomery_Int& g,
                                                                       size_t window_bits,
                                                                       bool const_time) {
   const size_t vectors = (ifma_digits(g._params().p().bits()) + 7) / 8;

   switch(vectors) {
      case 2: /* 415 - 830 bits */
         return make_monty_exp<2>(g, window_bits, const_time);
      case 3: /* 831 - 1246 bits */
         return make_monty_exp<3>(g, window_bits, const_time);
      case 4: /* 1247 - 1662 bits */
         return make_monty_exp<4>(g, window_bits, const_time);
      case 5: /* 1663 - 2078 bits */
         return make_monty_exp<5>(g, window_bits, const_time);
      case 6: /* 2079 - 2494 bits */
         return make_monty_exp<6>(g, window_bits, const_time);
      case 7: /* 2495 - 2910 bits */
         return make_monty_exp<7>(g, window_bits, const_time);
      case 8: /* 2911 - 3326 bits */
         return make_monty_exp<8>(g, window_bits, const_time);
      case 9: /* 3327 - 3742 bits */
         return make_monty_exp<9>(g, window_bits, const_time);
      case 10: /* 3743 - 4158 bits */
         return make_monty_exp<10>(g, window_bits, const_time);
      default:
         // Moduli under 415 bits or over 4158 bits do not seem of practical interest
         return nullptr;
   }
}

}  // namespace Botan
