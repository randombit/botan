/*
* Ed25519 field element
* (C) 2017 Ribose Inc
*     2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_FE_H_
#define BOTAN_ED25519_FE_H_

#include <botan/assert.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mp_core.h>
#include <array>
#include <optional>
#include <span>

namespace Botan {

consteval std::array<word, 256 / WordInfo<word>::bits> ed25519_fp_words() {
   // 2^255 - 19
   std::array<word, 256 / WordInfo<word>::bits> p{};
   for(auto& w : p) {
      w = WordInfo<word>::max;
   }
   p[0] -= 18;
   p[p.size() - 1] >>= 1;
   return p;
}

/**
* An element of the field Z/(2^255-19)
*
* The value is stored as saturated words. Aside from a value being reduced
* below 2^256 (rather than below p), there are no per-word bounds to track:
* additions and subtractions fold their carry or borrow back in immediately
* using 2^256 == 38 (mod p), and multiplications reduce below 2^255 using
* the same identity. Only serialization produces the canonical value.
*/
class Ed25519_FieldElement final {
   private:
      typedef word W;

      static constexpr size_t N = 256 / WordInfo<W>::bits;
      static constexpr size_t TOP_BIT = WordInfo<W>::bits - 1;
      static constexpr W TOP_MASK = WordInfo<W>::max >> 1;

      static constexpr std::array<W, N> P = ed25519_fp_words();

      /*
      * Fold a carry out of an addition back in using 2^256 == 38 (mod p).
      * The first fold can itself carry (only if the value was at least
      * 2^256 - 38); the second cannot.
      */
      constexpr void fold_carry(W carry) {
         for(size_t fold = 0; fold != 2; ++fold) {
            W c = 0;
            m_val[0] = word_add(m_val[0], static_cast<W>(carry * 38), &c);
            for(size_t i = 1; i != N; ++i) {
               m_val[i] = word_add(m_val[i], static_cast<W>(0), &c);
            }
            carry = c;
         }
      }

      /*
      * Fold a borrow out of a subtraction back in; as above but subtracting
      */
      constexpr void fold_borrow(W borrow) {
         for(size_t fold = 0; fold != 2; ++fold) {
            W b = 0;
            m_val[0] = word_sub(m_val[0], static_cast<W>(borrow * 38), &b);
            for(size_t i = 1; i != N; ++i) {
               m_val[i] = word_sub(m_val[i], static_cast<W>(0), &b);
            }
            borrow = b;
         }
      }

      /*
      * Reduce a full product below 2^255 using 2^256 == 38 and 2^255 == 19
      * (mod p). Follows the same approach as redc_crandall (mp_core.h) with
      * an extra folding step since the prime is one bit short of a word
      * multiple.
      */
      constexpr void reduce_wide(const std::array<W, 2 * N>& z) {
         // t = lo + 38 * hi < 39 * 2^256, so carry <= 38
         W carry = 0;
         for(size_t i = 0; i != N; ++i) {
            m_val[i] = word_madd3(z[i + N], W(38), z[i], &carry);
         }
         BOTAN_DEBUG_ASSERT(carry <= 38);

         // Fold the bits at and above 2^255 back in by 19. The first fold
         // leaves at most 19*77 above 2^255, the second leaves none.
         for(size_t fold = 0; fold != 2; ++fold) {
            const W top = (carry << 1) | (m_val[N - 1] >> TOP_BIT);
            m_val[N - 1] &= TOP_MASK;
            carry = 0;

            W c = 0;
            m_val[0] = word_add(m_val[0], static_cast<W>(top * 19), &c);
            for(size_t i = 1; i != N; ++i) {
               m_val[i] = word_add(m_val[i], static_cast<W>(0), &c);
            }
            // The top word was masked below 2^(bits-1) so this cannot carry out
            BOTAN_DEBUG_ASSERT(c == 0);
         }

         BOTAN_DEBUG_ASSERT((m_val[N - 1] >> TOP_BIT) == 0);
      }

      /*
      * Return the canonical value in [0,p)
      */
      constexpr std::array<W, N> canonical() const {
         // Fold the bit at 2^255, leaving a value below 2^255 + 19, then
         // conditionally subtract p once
         std::array<W, N> t = m_val;

         const W top = t[N - 1] >> TOP_BIT;
         t[N - 1] &= TOP_MASK;
         W c = 0;
         t[0] = word_add(t[0], static_cast<W>(top * 19), &c);
         for(size_t i = 1; i != N; ++i) {
            t[i] = word_add(t[i], static_cast<W>(0), &c);
         }

         std::array<W, N> r{};
         W borrow = 0;
         for(size_t i = 0; i != N; ++i) {
            r[i] = word_sub(t[i], P[i], &borrow);
         }
         CT::conditional_assign_mem(borrow, r.data(), t.data(), N);
         return r;
      }

   public:
      /**
      * Default zero initialization
      */
      constexpr Ed25519_FieldElement() : m_val{} {}

      constexpr static Ed25519_FieldElement zero() { return Ed25519_FieldElement(); }

      constexpr static Ed25519_FieldElement one() {
         Ed25519_FieldElement o;
         o.m_val[0] = 1;
         return o;
      }

      constexpr static Ed25519_FieldElement from_word(word x) {
         Ed25519_FieldElement r;
         r.m_val[0] = x;
         return r;
      }

      /**
      * Deserialize 32 little endian bytes, ignoring the high bit
      *
      * RFC 8032 5.1.3 requires that the encoded value (with the sign bit
      * cleared) is already less than p; a value in [p, 2^255) is rejected
      * rather than reduced.
      */
      static std::optional<Ed25519_FieldElement> deserialize(const uint8_t b[32]) {
         Ed25519_FieldElement r;
         for(size_t i = 0; i != N; ++i) {
            r.m_val[i] = load_le<W>(b, i);
         }
         r.m_val[N - 1] &= TOP_MASK;

         // Reject unless the value is already reduced, ie subtracting p borrows
         W borrow = 0;
         for(size_t i = 0; i != N; ++i) {
            (void)word_sub(r.m_val[i], P[i], &borrow);
         }
         if(borrow == 0) {
            return std::nullopt;
         }

         return r;
      }

      void serialize_to(std::span<uint8_t, 32> b) const {
         const auto w = canonical();
         for(size_t i = 0; i != N; ++i) {
            store_le(w[i], b.data() + sizeof(W) * i);
         }
      }

      constexpr bool is_zero() const {
         const auto w = canonical();
         if(std::is_constant_evaluated()) {
            for(auto x : w) {
               if(x != 0) {
                  return false;
               }
            }
            return true;
         }
         return CT::all_zeros(w.data(), w.size()).as_bool();
      }

      /*
      return true if f is in {1,3,5,...,q-2}
      return false if f is in {0,2,4,...,q-1}
      */
      constexpr bool is_negative() const { return (canonical()[0] & 1) == 1; }

      static constexpr Ed25519_FieldElement add(const Ed25519_FieldElement& a, const Ed25519_FieldElement& b) {
         Ed25519_FieldElement z;
         W carry = 0;
         for(size_t i = 0; i != N; ++i) {
            z.m_val[i] = word_add(a.m_val[i], b.m_val[i], &carry);
         }
         z.fold_carry(carry);
         return z;
      }

      static constexpr Ed25519_FieldElement sub(const Ed25519_FieldElement& a, const Ed25519_FieldElement& b) {
         Ed25519_FieldElement z;
         W borrow = 0;
         for(size_t i = 0; i != N; ++i) {
            z.m_val[i] = word_sub(a.m_val[i], b.m_val[i], &borrow);
         }
         z.fold_borrow(borrow);
         return z;
      }

      static constexpr Ed25519_FieldElement negate(const Ed25519_FieldElement& a) { return sub(zero(), a); }

      static constexpr Ed25519_FieldElement mul(const Ed25519_FieldElement& a, const Ed25519_FieldElement& b) {
         std::array<W, 2 * N> z;  // NOLINT(*-member-init)
         comba_mul<N>(z.data(), a.m_val.data(), b.m_val.data());
         Ed25519_FieldElement r;
         r.reduce_wide(z);
         return r;
      }

      constexpr Ed25519_FieldElement sqr() const {
         std::array<W, 2 * N> z;  // NOLINT(*-member-init)
         comba_sqr<N>(z.data(), m_val.data());
         Ed25519_FieldElement r;
         r.reduce_wide(z);
         return r;
      }

      constexpr Ed25519_FieldElement sqr_iter(size_t iter) const {
         auto r = *this;
         std::array<W, 2 * N> z;  // NOLINT(*-member-init)
         for(size_t i = 0; i != iter; ++i) {
            comba_sqr<N>(z.data(), r.m_val.data());
            r.reduce_wide(z);
         }
         return r;
      }

      // Return 2*a^2
      constexpr Ed25519_FieldElement sqr2() const {
         const auto z = sqr();
         return add(z, z);
      }

      constexpr Ed25519_FieldElement invert() const;

      constexpr Ed25519_FieldElement pow_22523() const;

      /**
      * If cond is set, assign other to this
      */
      constexpr void conditional_assign(CT::Choice cond, const Ed25519_FieldElement& other) {
         const W mask = cond.into_bitmask<W>();
         for(size_t i = 0; i != N; ++i) {
            m_val[i] = choose(mask, other.m_val[i], m_val[i]);
         }
      }

      /**
      * If cond is set, swap x and y
      */
      static constexpr void conditional_swap(CT::Choice cond, Ed25519_FieldElement& x, Ed25519_FieldElement& y) {
         const W mask = cond.into_bitmask<W>();
         for(size_t i = 0; i != N; ++i) {
            const W nx = choose(mask, y.m_val[i], x.m_val[i]);
            const W ny = choose(mask, x.m_val[i], y.m_val[i]);
            x.m_val[i] = nx;
            y.m_val[i] = ny;
         }
      }

   private:
      std::array<W, N> m_val;
};

inline constexpr Ed25519_FieldElement operator+(const Ed25519_FieldElement& x, const Ed25519_FieldElement& y) {
   return Ed25519_FieldElement::add(x, y);
}

inline constexpr Ed25519_FieldElement operator-(const Ed25519_FieldElement& x, const Ed25519_FieldElement& y) {
   return Ed25519_FieldElement::sub(x, y);
}

inline constexpr Ed25519_FieldElement operator*(const Ed25519_FieldElement& x, const Ed25519_FieldElement& y) {
   return Ed25519_FieldElement::mul(x, y);
}

inline constexpr Ed25519_FieldElement operator-(const Ed25519_FieldElement& x) {
   return Ed25519_FieldElement::negate(x);
}

constexpr Ed25519_FieldElement Ed25519_FieldElement::invert() const {
   auto t0 = this->sqr();
   auto t1 = t0.sqr_iter(2);
   t1 = *this * t1;
   t0 = t0 * t1;
   auto t2 = t0.sqr();
   t1 = t1 * t2;
   t2 = t1.sqr_iter(5);
   t1 = t2 * t1;
   t2 = t1.sqr_iter(10);
   t2 = t2 * t1;
   auto t3 = t2.sqr_iter(20);
   t2 = t3 * t2;
   t2 = t2.sqr_iter(10);
   t1 = t2 * t1;
   t2 = t1.sqr_iter(50);
   t2 = t2 * t1;
   t3 = t2.sqr_iter(100);
   t2 = t3 * t2;
   t2 = t2.sqr_iter(50);
   t1 = t2 * t1;
   t1 = t1.sqr_iter(5);

   t0 = t1 * t0;
   return t0;
}

constexpr Ed25519_FieldElement Ed25519_FieldElement::pow_22523() const {
   auto t0 = this->sqr();
   auto t1 = t0.sqr_iter(2);
   t1 = (*this) * t1;
   t0 = t0 * t1;
   t0 = t0.sqr();
   t0 = t1 * t0;
   t1 = t0.sqr_iter(5);
   t0 = t1 * t0;
   t1 = t0.sqr_iter(10);
   t1 = t1 * t0;
   auto t2 = t1.sqr_iter(20);
   t1 = t2 * t1;
   t1 = t1.sqr_iter(10);
   t0 = t1 * t0;
   t1 = t0.sqr_iter(50);
   t1 = t1 * t0;
   t2 = t1.sqr_iter(100);
   t1 = t2 * t1;
   t1 = t1.sqr_iter(50);
   t0 = t1 * t0;
   t0 = t0.sqr_iter(2);

   t0 = t0 * (*this);
   return t0;
}

}  // namespace Botan

#endif
