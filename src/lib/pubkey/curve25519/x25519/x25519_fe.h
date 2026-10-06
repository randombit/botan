/*
* (C) 2014,2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/*
* The field arithmetic is based on curve25519-donna-c64.c from
* https://github.com/agl/curve25519-donna
* revision 80ad9b9930c9baef5829dd2a235b6b7646d32a8e
*
* Copyright 2008, Google Inc.
* All rights reserved.
*
* Code released into the public domain.
*/

#ifndef BOTAN_X25519_FE_H_
#define BOTAN_X25519_FE_H_

#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/donna128.h>
#include <botan/internal/loadstor.h>
#include <array>
#include <span>

/*
* Everything here is force inlined so that the whole scalar multiplication
* compiles into a single function in each translation unit that uses it,
* without any out of line copies that the linker might merge.
*/

namespace Botan {

#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
typedef donna128 uint128_t;
#endif

/**
* An element of GF(2^255 - 19) in radix 2^51
*
* The value is sum(limb[i] * 2^(51*i)) over the five limbs. Limbs are not
* reduced below 2^51 between operations; instead the bounds from the original
* donna analysis are maintained:
*
* - mul and sqr return limbs below 2^52 (in fact at most 2^51 + 2^13)
* - adding two such results gives limbs below 2^53
* - subtracting two such results adds 8p to avoid underflow, giving limbs
*   below 2^52 + 2^54 < 2^55
* - mul, sqr and mul_a24 accept any such sum or difference as input
*
* The ladder never chains an addition or subtraction into another addition or
* subtraction without a multiplication or squaring in between.
*/
class X25519_FE final {
   public:
      /// The zero element
      constexpr X25519_FE() : m_v{} {}

      constexpr static X25519_FE one() {
         X25519_FE r;
         r.m_v[0] = 1;
         return r;
      }

      /**
      * Decode 32 little endian bytes
      *
      * The high bit of the final byte is ignored (RFC 7748 Section 5); the
      * value is not reduced, which is fine since the inputs are only used as
      * multiplication operands.
      */
      BOTAN_FORCE_INLINE static X25519_FE decode(std::span<const uint8_t, 32> in) {
         X25519_FE r;
         r.m_v[0] = load_le<uint64_t>(in.data(), 0) & MASK_51;
         r.m_v[1] = (load_le<uint64_t>(in.data() + 6, 0) >> 3) & MASK_51;
         r.m_v[2] = (load_le<uint64_t>(in.data() + 12, 0) >> 6) & MASK_51;
         r.m_v[3] = (load_le<uint64_t>(in.data() + 19, 0) >> 1) & MASK_51;
         r.m_v[4] = (load_le<uint64_t>(in.data() + 24, 0) >> 12) & MASK_51;
         return r;
      }

      /**
      * Encode the canonical value in [0,p) as 32 little endian bytes
      */
      BOTAN_FORCE_INLINE void encode(std::span<uint8_t, 32> out) const {
         auto t0 = uint128_t(m_v[0]);
         auto t1 = uint128_t(m_v[1]);
         auto t2 = uint128_t(m_v[2]);
         auto t3 = uint128_t(m_v[3]);
         auto t4 = uint128_t(m_v[4]);

         for(size_t i = 0; i != 2; ++i) {
            t1 += t0 >> 51U;
            t0 &= MASK_51;
            t2 += t1 >> 51U;
            t1 &= MASK_51;
            t3 += t2 >> 51U;
            t2 &= MASK_51;
            t4 += t3 >> 51U;
            t3 &= MASK_51;
            t0 += (t4 >> 51U) * 19;
            t4 &= MASK_51;
         }

         /* now t is between 0 and 2^255-1, properly carried. */
         /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

         t0 += 19;

         t1 += t0 >> 51U;
         t0 &= MASK_51;
         t2 += t1 >> 51U;
         t1 &= MASK_51;
         t3 += t2 >> 51U;
         t2 &= MASK_51;
         t4 += t3 >> 51U;
         t3 &= MASK_51;
         t0 += (t4 >> 51U) * 19;
         t4 &= MASK_51;

         /* now between 19 and 2^255-1 in both cases, and offset by 19. */

         t0 += 0x8000000000000 - 19;
         t1 += 0x8000000000000 - 1;
         t2 += 0x8000000000000 - 1;
         t3 += 0x8000000000000 - 1;
         t4 += 0x8000000000000 - 1;

         /* now between 2^255 and 2^256-20, and offset by 2^255. */

         t1 += t0 >> 51U;
         t0 &= MASK_51;
         t2 += t1 >> 51U;
         t1 &= MASK_51;
         t3 += t2 >> 51U;
         t2 &= MASK_51;
         t4 += t3 >> 51U;
         t3 &= MASK_51;
         t4 &= MASK_51;

         store_le(out.data(),
                  combine_lower(t0, 0, t1, 51),
                  combine_lower(t1, 13, t2, 38),
                  combine_lower(t2, 26, t3, 25),
                  combine_lower(t3, 39, t4, 12));
      }

      BOTAN_FORCE_INLINE friend X25519_FE operator+(const X25519_FE& a, const X25519_FE& b) {
         X25519_FE r;
         for(size_t i = 0; i != 5; ++i) {
            r.m_v[i] = a.m_v[i] + b.m_v[i];
         }
         return r;
      }

      /**
      * Subtraction, computed as a + 8p - b so that no limb underflows
      */
      BOTAN_FORCE_INLINE friend X25519_FE operator-(const X25519_FE& a, const X25519_FE& b) {
         // 8p = 2^258 - 152 in radix 2^51, with each limb biased to be positive
         constexpr uint64_t two54m152 = (static_cast<uint64_t>(1) << 54) - 152;
         constexpr uint64_t two54m8 = (static_cast<uint64_t>(1) << 54) - 8;

         X25519_FE r;
         r.m_v[0] = a.m_v[0] + two54m152 - b.m_v[0];
         r.m_v[1] = a.m_v[1] + two54m8 - b.m_v[1];
         r.m_v[2] = a.m_v[2] + two54m8 - b.m_v[2];
         r.m_v[3] = a.m_v[3] + two54m8 - b.m_v[3];
         r.m_v[4] = a.m_v[4] + two54m8 - b.m_v[4];
         return r;
      }

      BOTAN_FORCE_INLINE friend X25519_FE operator*(const X25519_FE& a, const X25519_FE& b) {
         const uint64_t a0 = a.m_v[0];
         const uint64_t a1 = a.m_v[1];
         const uint64_t a2 = a.m_v[2];
         const uint64_t a3 = a.m_v[3];
         const uint64_t a4 = a.m_v[4];

         const uint64_t b0 = b.m_v[0];
         const uint64_t b1 = b.m_v[1];
         const uint64_t b2 = b.m_v[2];
         const uint64_t b3 = b.m_v[3];
         const uint64_t b4 = b.m_v[4];

         // Products that wrap past 2^255 are multiplied by 19 since 2^255 == 19 (mod p)
         const uint64_t b1_19 = b1 * 19;
         const uint64_t b2_19 = b2 * 19;
         const uint64_t b3_19 = b3 * 19;
         const uint64_t b4_19 = b4 * 19;

         const uint128_t t0 = mul(a0, b0) + mul(a1, b4_19) + mul(a2, b3_19) + mul(a3, b2_19) + mul(a4, b1_19);
         const uint128_t t1 = mul(a0, b1) + mul(a1, b0) + mul(a2, b4_19) + mul(a3, b3_19) + mul(a4, b2_19);
         const uint128_t t2 = mul(a0, b2) + mul(a1, b1) + mul(a2, b0) + mul(a3, b4_19) + mul(a4, b3_19);
         const uint128_t t3 = mul(a0, b3) + mul(a1, b2) + mul(a2, b1) + mul(a3, b0) + mul(a4, b4_19);
         const uint128_t t4 = mul(a0, b4) + mul(a1, b3) + mul(a2, b2) + mul(a3, b1) + mul(a4, b0);

         return carry(t0, t1, t2, t3, t4);
      }

      BOTAN_FORCE_INLINE X25519_FE sqr() const {
         const uint64_t a0 = m_v[0];
         const uint64_t a1 = m_v[1];
         const uint64_t a2 = m_v[2];
         const uint64_t a3 = m_v[3];
         const uint64_t a4 = m_v[4];

         const uint64_t a0_2 = a0 * 2;
         const uint64_t a1_2 = a1 * 2;
         const uint64_t a2_38 = a2 * 38;
         const uint64_t a3_19 = a3 * 19;
         const uint64_t a4_19 = a4 * 19;
         const uint64_t a4_38 = a4_19 * 2;

         const uint128_t t0 = mul(a0, a0) + mul(a1, a4_38) + mul(a3, a2_38);
         const uint128_t t1 = mul(a0_2, a1) + mul(a2, a4_38) + mul(a3, a3_19);
         const uint128_t t2 = mul(a0_2, a2) + mul(a1, a1) + mul(a3, a4_38);
         const uint128_t t3 = mul(a0_2, a3) + mul(a1_2, a2) + mul(a4, a4_19);
         const uint128_t t4 = mul(a0_2, a4) + mul(a1_2, a3) + mul(a2, a2);

         return carry(t0, t1, t2, t3, t4);
      }

      BOTAN_FORCE_INLINE X25519_FE sqr_n(size_t n) const {
         X25519_FE r = *this;
         for(size_t i = 0; i != n; ++i) {
            r = r.sqr();
         }
         return r;
      }

      /**
      * Multiply by a24 = (A - 2) / 4 = 121665, the ladder constant
      */
      BOTAN_FORCE_INLINE X25519_FE mul_a24() const {
         constexpr uint64_t a24 = 121665;

         X25519_FE r;

         uint128_t t = mul(m_v[0], a24);
         r.m_v[0] = t & MASK_51;

         t = mul(m_v[1], a24) + carry_shift(t, 51);
         r.m_v[1] = t & MASK_51;

         t = mul(m_v[2], a24) + carry_shift(t, 51);
         r.m_v[2] = t & MASK_51;

         t = mul(m_v[3], a24) + carry_shift(t, 51);
         r.m_v[3] = t & MASK_51;

         t = mul(m_v[4], a24) + carry_shift(t, 51);
         r.m_v[4] = t & MASK_51;

         r.m_v[0] += carry_shift(t, 51) * 19;

         return r;
      }

      /**
      * Inversion via FLT
      *
      * Returns zero for a zero input, which is what the ladder relies on for
      * the identity (and the all-zero shared secret for low order points).
      */
      BOTAN_FORCE_INLINE X25519_FE invert() const {
         const auto& z = *this;

         auto a = z.sqr();     // 2
         auto t = a.sqr_n(2);  // 8
         auto b = t * z;       // 9
         a = b * a;            // 11
         t = a.sqr();          // 22
         b = t * b;            // 2^5 - 2^0 = 31
         t = b.sqr_n(5);       // 2^10 - 2^5
         b = t * b;            // 2^10 - 2^0
         t = b.sqr_n(10);      // 2^20 - 2^10
         auto c = t * b;       // 2^20 - 2^0
         t = c.sqr_n(20);      // 2^40 - 2^20
         t = t * c;            // 2^40 - 2^0
         t = t.sqr_n(10);      // 2^50 - 2^10
         b = t * b;            // 2^50 - 2^0
         t = b.sqr_n(50);      // 2^100 - 2^50
         c = t * b;            // 2^100 - 2^0
         t = c.sqr_n(100);     // 2^200 - 2^100
         t = t * c;            // 2^200 - 2^0
         t = t.sqr_n(50);      // 2^250 - 2^50
         t = t * b;            // 2^250 - 2^0
         t = t.sqr_n(5);       // 2^255 - 2^5
         return t * a;         // 2^255 - 21
      }

      /**
      * Swap a and b if the mask is set
      */
      BOTAN_FORCE_INLINE static void conditional_swap(CT::Mask<uint64_t> swap, X25519_FE& a, X25519_FE& b) {
         for(size_t i = 0; i != 5; ++i) {
            const uint64_t x = swap.if_set_return(a.m_v[i] ^ b.m_v[i]);
            a.m_v[i] ^= x;
            b.m_v[i] ^= x;
         }
      }

   private:
      static constexpr uint64_t MASK_51 = (static_cast<uint64_t>(1) << 51) - 1;

      BOTAN_FORCE_INLINE static uint128_t mul(uint64_t a, uint64_t b) { return uint128_t(a) * b; }

      /**
      * Propagate the carries of a product, leaving limbs below 2^52
      */
      BOTAN_FORCE_INLINE static X25519_FE carry(
         const uint128_t& t0, uint128_t t1, uint128_t t2, uint128_t t3, uint128_t t4) {
         X25519_FE r;

         r.m_v[0] = t0 & MASK_51;
         t1 += carry_shift(t0, 51);
         r.m_v[1] = t1 & MASK_51;
         t2 += carry_shift(t1, 51);
         r.m_v[2] = t2 & MASK_51;
         t3 += carry_shift(t2, 51);
         r.m_v[3] = t3 & MASK_51;
         t4 += carry_shift(t3, 51);
         r.m_v[4] = t4 & MASK_51;

         // The carry out of the top limb wraps to 2^255 == 19
         r.m_v[0] += carry_shift(t4, 51) * 19;
         r.m_v[1] += r.m_v[0] >> 51;
         r.m_v[0] &= MASK_51;

         return r;
      }

      std::array<uint64_t, 5> m_v;
};

/**
* The X25519 Montgomery ladder (RFC 7748 Section 5)
*
* Computes the u-coordinate of [k]P where P is the point with u-coordinate u.
* The scalar must already be clamped.
*/
BOTAN_FORCE_INLINE void x25519_ladder(std::span<uint8_t, 32> out,
                                      std::span<const uint8_t, 32> k,
                                      std::span<const uint8_t, 32> u) {
   const auto x1 = X25519_FE::decode(u);

   auto x2 = X25519_FE::one();
   auto z2 = X25519_FE();
   auto x3 = x1;
   auto z3 = X25519_FE::one();

   auto swap = CT::Mask<uint64_t>::cleared();

   // Bit 255 of a clamped scalar is always zero, so start at bit 254
   for(size_t t = 255; t-- > 0;) {
      const auto kt = CT::Mask<uint64_t>::expand_bit(static_cast<uint64_t>(k[t / 8]), t % 8);
      swap = swap ^ kt;
      X25519_FE::conditional_swap(swap, x2, x3);
      X25519_FE::conditional_swap(swap, z2, z3);
      swap = kt;

      const auto A = x2 + z2;
      const auto B = x2 - z2;
      const auto C = x3 + z3;
      const auto D = x3 - z3;
      const auto AA = A.sqr();
      const auto BB = B.sqr();
      const auto E = AA - BB;
      const auto DA = D * A;
      const auto CB = C * B;

      x3 = (DA + CB).sqr();
      z3 = x1 * (DA - CB).sqr();
      x2 = AA * BB;
      z2 = E * (AA + E.mul_a24());
   }

   X25519_FE::conditional_swap(swap, x2, x3);
   X25519_FE::conditional_swap(swap, z2, z3);

   const auto result = x2 * z2.invert();
   result.encode(out);
}

}  // namespace Botan

#endif
