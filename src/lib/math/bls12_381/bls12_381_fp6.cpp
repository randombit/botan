/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/bls12_381_tower.h>

#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

CT::Choice Fp6::is_zero() const {
   return m_c0.is_zero() && m_c1.is_zero() && m_c2.is_zero();
}

Fp6 Fp6::add(const Fp6& x) const {
   return Fp6(m_c0 + x.m_c0, m_c1 + x.m_c1, m_c2 + x.m_c2);
}

Fp6 Fp6::sub(const Fp6& x) const {
   return Fp6(m_c0 - x.m_c0, m_c1 - x.m_c1, m_c2 - x.m_c2);
}

Fp6 Fp6::negate() const {
   return Fp6(m_c0.negate(), m_c1.negate(), m_c2.negate());
}

Fp6 Fp6::mul(const Fp6& x) const {
   // Karatsuba multiplication using 6 Fp2 multiplications, with xi = u+1:
   // c0 = t0 + xi*((a1+a2)(b1+b2) - t1 - t2)
   // c1 = (a0+a1)(b0+b1) - t0 - t1 + xi*t2
   // c2 = (a0+a2)(b0+b2) - t0 - t2 + t1
   const auto t0 = m_c0 * x.m_c0;
   const auto t1 = m_c1 * x.m_c1;
   const auto t2 = m_c2 * x.m_c2;

   const auto s12 = (m_c1 + m_c2) * (x.m_c1 + x.m_c2);
   const auto s01 = (m_c0 + m_c1) * (x.m_c0 + x.m_c1);
   const auto s02 = (m_c0 + m_c2) * (x.m_c0 + x.m_c2);

   return Fp6((s12 - t1 - t2).mul_by_nonresidue() + t0, s01 - t0 - t1 + t2.mul_by_nonresidue(), s02 - t0 - t2 + t1);
}

Fp6 Fp6::square() const {
   const auto s0 = m_c0.square();
   const auto ab = m_c0 * m_c1;
   const auto s1 = ab + ab;
   const auto s2 = (m_c0 - m_c1 + m_c2).square();
   const auto bc = m_c1 * m_c2;
   const auto s3 = bc + bc;
   const auto s4 = m_c2.square();

   return Fp6(s3.mul_by_nonresidue() + s0, s4.mul_by_nonresidue() + s1, s1 + s2 + s3 - s0 - s4);
}

Fp6 Fp6::invert() const {
   const auto c0 = m_c0.square() - (m_c1 * m_c2).mul_by_nonresidue();
   const auto c1 = m_c2.square().mul_by_nonresidue() - (m_c0 * m_c1);
   const auto c2 = m_c1.square() - (m_c0 * m_c2);

   const auto t = (((m_c1 * c2) + (m_c2 * c1)).mul_by_nonresidue() + (m_c0 * c0)).invert();

   return Fp6(t * c0, t * c1, t * c2);
}

Fp6 Fp6::mul_by_nonresidue() const {
   // (c0 + c1*v + c2*v^2)*v = c2*(u+1) + c0*v + c1*v^2 using v^3 = u+1
   return Fp6(m_c2.mul_by_nonresidue(), m_c0, m_c1);
}

Fp6 Fp6::mul_by_1(const FieldElement2& b1) const {
   return Fp6((m_c2 * b1).mul_by_nonresidue(), m_c0 * b1, m_c1 * b1);
}

Fp6 Fp6::mul_by_01(const FieldElement2& b0, const FieldElement2& b1) const {
   const auto a_a = m_c0 * b0;
   const auto b_b = m_c1 * b1;

   const auto t1 = (m_c2 * b1).mul_by_nonresidue() + a_a;
   const auto t2 = (b0 + b1) * (m_c0 + m_c1) - a_a - b_b;
   const auto t3 = m_c2 * b0 + b_b;

   return Fp6(t1, t2, t3);
}

Fp6 Fp6::frobenius_map() const {
   // (u+1)^((p-1)/3)
   constexpr auto FP6_FROBENIUS_C1 = FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
      hex_to_words<word>(
         "18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071"));

   // (u+1)^((2p-2)/3)
   constexpr auto FP6_FROBENIUS_C2 = FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "14e56d3f1564853a14e4f04fe2db9068a20d1b8c7e88102450880866309b7e2c2af322533285a5d5890dc9e4867545c3"),
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

   return Fp6(m_c0.conjugate(), m_c1.conjugate() * FP6_FROBENIUS_C1, m_c2.conjugate() * FP6_FROBENIUS_C2);
}

CT::Choice Fp6::operator==(const Fp6& other) const {
   return (m_c0 == other.m_c0) && (m_c1 == other.m_c1) && (m_c2 == other.m_c2);
}

void Fp6::_conditional_assign(CT::Choice cnd, const Fp6& other) {
   m_c0._conditional_assign(cnd, other.m_c0);
   m_c1._conditional_assign(cnd, other.m_c1);
   m_c2._conditional_assign(cnd, other.m_c2);
}

}  // namespace Botan::BLS12_381
