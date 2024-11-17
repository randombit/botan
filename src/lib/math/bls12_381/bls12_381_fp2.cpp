/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/bls12_381_fields.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

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

void FieldElement2::_conditional_assign(CT::Choice cnd, const FieldElement2& other) {
   m_c0._conditional_assign(cnd, other.m_c0);
   m_c1._conditional_assign(cnd, other.m_c1);
}

CT::Choice FieldElement2::_is_lexicographically_largest() const {
   return m_c1._is_lexicographically_largest() || (m_c1.is_zero() && m_c0._is_lexicographically_largest());
}

std::optional<FieldElement2> FieldElement2::sqrt() const {
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

   auto fp2_pow = [](const FieldElement2& x, std::span<const word> exp) -> FieldElement2 {
      auto r = FieldElement2::one();
      for(size_t i = 0; i != exp.size(); ++i) {
         const word w = exp[exp.size() - 1 - i];
         for(size_t b = 0; b != WordInfo<word>::bits; ++b) {
            r = r.square();
            // The exponent is a public constant so this branch leaks nothing
            if(((w >> (WordInfo<word>::bits - 1 - b)) & 1) == 1) {
               r = r * x;
            }
         }
      }
      return r;
   };

   // a1 = x^((p-3)/4)
   const auto a1 = fp2_pow(*this, FP2_SQRT_EXP);

   // alpha = a1^2 * x = x^((p-1)/2)
   const auto alpha = a1.square() * (*this);

   // x0 = a1 * x = x^((p+1)/4)
   const auto x0 = a1 * (*this);

   // If alpha == -1 the square root is x0 * u; otherwise it is
   // (1 + alpha)^((p-1)/2) * x0. In the first case 1 + alpha == 0 so the
   // generic computation yields zero and is overridden in constant time.
   auto candidate = fp2_pow(alpha + FieldElement2::one(), FP2_P_HALF) * x0;

   const auto x0_u = FieldElement2(x0.c1().negate(), x0.c0());
   const auto alpha_is_neg_one = (alpha == FieldElement2::one().negate());
   candidate._conditional_assign(alpha_is_neg_one, x0_u);

   if((candidate.square() == (*this)).as_bool()) {
      return candidate;
   } else {
      return {};
   }
}

}  // namespace Botan::BLS12_381
