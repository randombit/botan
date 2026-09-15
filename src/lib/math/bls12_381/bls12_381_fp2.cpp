/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/bls12_381_fields.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

namespace {

// Addition chain for (p-11)/16, found using https://github.com/mmcloughlin/addchain
FieldElement2 pow_p_minus_11_over_16(const FieldElement2& x) {
   auto t3 = x.square();
   auto t4 = t3.square();
   auto z = t4 * x;
   auto t6 = t4.square();
   auto t7 = t6 * x;
   auto t9 = t3 * t7;
   auto t25 = t6 * t7;
   auto t1 = t7 * t9;
   auto t18 = t1 * z;
   auto t10 = t18 * x;
   auto t11 = t10.square();
   auto t5 = t11 * t3;
   auto t2 = t5 * x;
   auto t23 = t11 * t18;
   auto t15 = t23 * t3;
   auto t0 = t23 * t6;
   auto t21 = t0 * t6;
   auto t12 = t10 * t23;
   auto t20 = t12 * t3;
   auto t17 = t10 * t21;
   auto t8 = t17 * t4;
   auto t13 = t0 * t11;
   t10 *= t8;
   auto t16 = t10 * t3;
   t3 = t1 * t10;
   auto t22 = t3 * t6;
   t5 *= t13;
   t11 = t4 * t5;
   t6 = t25 * t5;
   auto t19 = t1 * t11;
   auto t14 = t25 * t6;
   auto t24 = t14 * t4;
   t4 = t1 * t19;
   t6 = t1 * t14;
   t1 *= t4;
   auto t26 = t14 * t5;
   t26.square_n(8);
   t25 *= t26;
   t25.square_n(11);
   t25 *= t6;
   t25.square_n(11);
   t24 *= t25;
   t24.square_n(8);
   t24 *= t1;
   t24.square_n(7);
   t23 *= t24;
   t23.square_n(9);
   t23 *= t20;
   t23.square_n(10);
   t22 *= t23;
   t22.square_n(7);
   t21 *= t22;
   t21.square_n(9);
   t21 *= t8;
   t21.square_n(6);
   t21 *= t18;
   t21.square_n(11);
   t20 *= t21;
   t20.square_n(9);
   t20 *= t4;
   t20.square_n(10);
   t19 *= t20;
   t19.square_n(6);
   t18 *= t19;
   t18.square_n(10);
   t17 *= t18;
   t17.square_n(9);
   t16 *= t17;
   t16.square_n(11);
   t15 *= t16;
   t15.square_n(10);
   t14 *= t15;
   t14.square_n(9);
   t13 *= t14;
   t13.square_n(9);
   t13 *= t5;
   t13.square_n(8);
   t12 *= t13;
   t12.square_n(10);
   t11 *= t12;
   t11.square_n(9);
   t10 *= t11;
   t10.square_n(12);
   t10 *= t8;
   t10.square_n(5);
   t9 *= t10;
   t9.square_n(11);
   t8 *= t9;
   t8.square_n(7);
   t7 *= t8;
   t7.square_n(13);
   t6 *= t7;
   t6.square_n(9);
   t5 *= t6;
   t5.square_n(8);
   t5 *= t1;
   t5.square_n(8);
   t4 *= t5;
   t4.square_n(11);
   t3 *= t4;
   t3.square_n(8);
   t3 *= t1;
   t3.square_n(8);
   t3 *= t1;
   t3.square_n(6);
   t2 *= t3;
   t2.square_n(10);
   t2 *= t1;
   t2.square_n(9);
   t2 *= t1;
   t2.square_n(8);
   t2 *= t1;
   t2.square_n(8);
   t2 *= t1;
   t2.square_n(8);
   t1 *= t2;
   t1.square_n(7);
   t0 *= t1;
   t0.square_n(4);
   z *= t0;
   z = z.square();
   return z;
}

}  // namespace

FieldElement2 pow_p2_minus_9_over_16(const FieldElement2& x) {
   const auto t = pow_p_minus_11_over_16(x);
   const auto t2 = t.square();
   const auto t4 = t2.square();
   const auto t8 = t4.square();
   const auto t11 = t8 * t2 * t;

   const auto x2 = x.square();
   const auto x3 = x2 * x;
   const auto x6 = x3.square();
   const auto x7 = x6 * x;

   // (p^2-9)/16 = q*p + 11*q + 7 for q = (p-11)/16
   return t.conjugate() * t11 * x7;
}

//static
std::optional<FieldElement2> FieldElement2::deserialize(std::span<const uint8_t> bytes) {
   if(bytes.size() != FieldElement2::BYTES) {
      return {};
   }

   // The c1 coefficient is encoded first
   const auto c1 = FieldElement::deserialize(bytes.first(FieldElement::BYTES));
   const auto c0 = FieldElement::deserialize(bytes.last(FieldElement::BYTES));

   if(!c0 || !c1) {
      return {};
   }

   return FieldElement2(*c0, *c1);
}

void FieldElement2::serialize_to(std::span<uint8_t, FieldElement2::BYTES> bytes) const {
   m_c1.serialize_to(bytes.first<FieldElement::BYTES>());
   m_c0.serialize_to(bytes.last<FieldElement::BYTES>());
}

CT::Choice FieldElement2::is_zero() const {
   return m_c0.is_zero() && m_c1.is_zero();
}

FieldElement2 FieldElement2::add(const FieldElement2& x) const {
   return FieldElement2(m_c0 + x.m_c0, m_c1 + x.m_c1);
}

FieldElement2 FieldElement2::sub(const FieldElement2& x) const {
   return FieldElement2(m_c0 - x.m_c0, m_c1 - x.m_c1);
}

FieldElement2 FieldElement2::mul(const FieldElement2& x) const {
   // Karatsuba multiplication using 3 base field multiplications:
   // (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + ((a0+a1)(b0+b1) - a0*b0 - a1*b1)*u
   const auto v0 = m_c0 * x.m_c0;
   const auto v1 = m_c1 * x.m_c1;
   const auto s = (m_c0 + m_c1) * (x.m_c0 + x.m_c1);

   return FieldElement2(v0 - v1, s - v0 - v1);
}

FieldElement2 FieldElement2::square() const {
   // Complex squaring using 2 base field multiplications:
   // (a + b*u)^2 = (a+b)(a-b) + (2ab)*u
   const auto t0 = (m_c0 + m_c1) * (m_c0 - m_c1);
   const auto t1 = m_c0 * m_c1;

   return FieldElement2(t0, t1 + t1);
}

void FieldElement2::square_n(size_t n) {
   for(size_t i = 0; i != n; ++i) {
      (*this) = this->square();
   }
}

FieldElement2 FieldElement2::negate() const {
   return FieldElement2(m_c0.negate(), m_c1.negate());
}

FieldElement2 FieldElement2::conjugate() const {
   return FieldElement2(m_c0, m_c1.negate());
}

FieldElement2 FieldElement2::mul_by_nonresidue() const {
   // (a + b*u)(u + 1) = (a - b) + (a + b)*u using u^2 = -1
   return FieldElement2(m_c0 - m_c1, m_c0 + m_c1);
}

FieldElement2 FieldElement2::invert() const {
   /*
   * We wish to compute the inverse of (a + b*u) where u^2 = -1
   *
   * Consider the identity (a + b*u)(a - b*u) = a^2 + b^2. Shifting
   * the terms implies the inverse of (a + b*u) is (a - b*u)/(a^2 + b^2)
   */

   // First compute (a^2 + b^2)^-1
   const auto ninv = (m_c0.square() + m_c1.square()).invert();

   // Apply the inverse then additional negate c1
   return FieldElement2(m_c0 * ninv, (m_c1 * ninv).negate());
}

CT::Choice FieldElement2::operator==(const FieldElement2& other) const {
   return (m_c0 == other.m_c0) && (m_c1 == other.m_c1);
}

void FieldElement2::conditional_assign(CT::Choice cnd, const FieldElement2& other) {
   m_c0.conditional_assign(cnd, other.m_c0);
   m_c1.conditional_assign(cnd, other.m_c1);
}

CT::Choice FieldElement2::_is_lexicographically_largest() const {
   return m_c1._is_lexicographically_largest() || (m_c1.is_zero() && m_c0._is_lexicographically_largest());
}

CT::Option<FieldElement2> FieldElement2::sqrt() const {
   // Algorithm 9 of https://eprint.iacr.org/2012/685.pdf for q == 3 (mod 4)

   constexpr auto FP2_P = hex_to_words<word>(
      "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

   // (p-3)/4; since p == 3 (mod 4) this is p >> 2
   constexpr auto FP2_SQRT_EXP = [FP2_P] {
      auto x = FP2_P;
      shift_right<2>(x);
      return x;
   }();

   // (p-1)/2, ie p >> 1
   constexpr auto FP2_P_HALF = [FP2_P] {
      auto x = FP2_P;
      shift_right<1>(x);
      return x;
   }();

   // a1 = x^((p-3)/4)
   const auto a1 = pow_msb(*this, FP2_SQRT_EXP);

   // alpha = a1^2 * x = x^((p-1)/2)
   const auto alpha = a1.square() * (*this);

   // x0 = a1 * x = x^((p+1)/4)
   const auto x0 = a1 * (*this);

   // If alpha == -1 the square root is x0 * u; otherwise it is
   // (1 + alpha)^((p-1)/2) * x0. In the first case 1 + alpha == 0 so the
   // generic computation yields zero and is overridden in constant time.
   auto candidate = pow_msb(alpha + FieldElement2::one(), FP2_P_HALF) * x0;

   const auto x0_u = FieldElement2(x0.c1().negate(), x0.c0());
   const auto alpha_is_neg_one = (alpha == FieldElement2::one().negate());
   candidate.conditional_assign(alpha_is_neg_one, x0_u);

   return CT::Option<FieldElement2>(candidate, candidate.square() == (*this));
}

}  // namespace Botan::BLS12_381
