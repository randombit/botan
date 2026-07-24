/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/bls12_381_tower.h>

#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

CT::Choice Fp12::is_zero() const {
   return m_c0.is_zero() && m_c1.is_zero();
}

void Fp12::serialize_to(std::span<uint8_t, Fp12::BYTES> bytes) const {
   constexpr size_t fe_bytes = FieldElement::BYTES;

   const std::array<const FieldElement*, 12> coeffs = {
      &m_c0.c0().c0(),
      &m_c0.c0().c1(),
      &m_c0.c1().c0(),
      &m_c0.c1().c1(),
      &m_c0.c2().c0(),
      &m_c0.c2().c1(),
      &m_c1.c0().c0(),
      &m_c1.c0().c1(),
      &m_c1.c1().c0(),
      &m_c1.c1().c1(),
      &m_c1.c2().c0(),
      &m_c1.c2().c1(),
   };

   for(size_t i = 0; i != coeffs.size(); ++i) {
      coeffs[i]->serialize_to(bytes.subspan(i * fe_bytes).first<fe_bytes>());
   }
}

Fp12 Fp12::add(const Fp12& x) const {
   return Fp12(m_c0 + x.m_c0, m_c1 + x.m_c1);
}

Fp12 Fp12::sub(const Fp12& x) const {
   return Fp12(m_c0 - x.m_c0, m_c1 - x.m_c1);
}

Fp12 Fp12::negate() const {
   return Fp12(m_c0.negate(), m_c1.negate());
}

Fp12 Fp12::mul(const Fp12& x) const {
   // Karatsuba multiplication using 3 Fp6 multiplications, with w^2 = v
   const auto aa = m_c0 * x.m_c0;
   const auto bb = m_c1 * x.m_c1;
   const auto c1 = (m_c1 + m_c0) * (x.m_c0 + x.m_c1) - aa - bb;

   return Fp12(bb.mul_by_nonresidue() + aa, c1);
}

Fp12 Fp12::square() const {
   const auto ab = m_c0 * m_c1;
   const auto c0c1 = m_c0 + m_c1;
   const auto c0 = (m_c1.mul_by_nonresidue() + m_c0) * c0c1 - ab - ab.mul_by_nonresidue();
   const auto c1 = ab + ab;

   return Fp12(c0, c1);
}

Fp12 Fp12::invert() const {
   const auto t = (m_c0.square() - m_c1.square().mul_by_nonresidue()).invert();
   return Fp12(m_c0 * t, (m_c1 * t).negate());
}

Fp12 Fp12::conjugate() const {
   return Fp12(m_c0, m_c1.negate());
}

Fp12 Fp12::mul_by_014(const FieldElement2& b0, const FieldElement2& b1, const FieldElement2& b4) const {
   const auto aa = m_c0.mul_by_01(b0, b1);
   const auto bb = m_c1.mul_by_1(b4);
   const auto c1 = (m_c1 + m_c0).mul_by_01(b0, b1 + b4) - aa - bb;

   return Fp12(bb.mul_by_nonresidue() + aa, c1);
}

Fp12 Fp12::frobenius_map() const {
   // (u+1)^((p-1)/6)
   constexpr auto FP12_FROBENIUS_C1 = FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "08f2220fb0fb66eb1ce393ea5daace4da35baecab2dc29ee97e83cccd117228fc6695f92b50a831307089552b319d465"),
      hex_to_words<word>(
         "110eefda88847faf2e3813cbe5a0de89c11b9cba40a8e8d0cf4895d42599d3945842a06bfc497cecb2f66aad4ce5d646"));

   const auto c0 = m_c0.frobenius_map();
   const auto c1 = m_c1.frobenius_map();

   // c1 *= (u+1)^((p-1)/6)
   return Fp12(c0, c1.mul_by_01(FP12_FROBENIUS_C1, FieldElement2::zero()));
}

Fp12 Fp12::cyclotomic_square() const {
   // See "Guide to Pairing-Based Cryptography", Algorithm 5.5.4

   // Squaring in Fp4 = Fp2[w]/(w^2 - v), on coefficients directly
   auto fp4_square = [](const FieldElement2& a, const FieldElement2& b) -> std::pair<FieldElement2, FieldElement2> {
      const auto t0 = a.square();
      const auto t1 = b.square();
      const auto c0 = t1.mul_by_nonresidue() + t0;
      const auto c1 = (a + b).square() - t0 - t1;
      return {c0, c1};
   };

   auto z0 = m_c0.c0();
   auto z4 = m_c0.c1();
   auto z3 = m_c0.c2();
   auto z2 = m_c1.c0();
   auto z1 = m_c1.c1();
   auto z5 = m_c1.c2();

   const auto [t0a, t1a] = fp4_square(z0, z1);

   z0 = t0a - z0;
   z0 = z0 + z0 + t0a;
   z1 = t1a + z1;
   z1 = z1 + z1 + t1a;

   const auto [t0b, t1b] = fp4_square(z2, z3);
   const auto [t2, t3] = fp4_square(z4, z5);

   z4 = t0b - z4;
   z4 = z4 + z4 + t0b;
   z5 = t1b + z5;
   z5 = z5 + z5 + t1b;

   const auto t = t3.mul_by_nonresidue();
   z2 = t + z2;
   z2 = z2 + z2 + t;
   z3 = t2 - z3;
   z3 = z3 + z3 + t2;

   return Fp12(Fp6(z0, z4, z3), Fp6(z2, z1, z5));
}

CT::Choice Fp12::operator==(const Fp12& other) const {
   return (m_c0 == other.m_c0) && (m_c1 == other.m_c1);
}

void Fp12::_conditional_assign(CT::Choice cnd, const Fp12& other) {
   m_c0._conditional_assign(cnd, other.m_c0);
   m_c1._conditional_assign(cnd, other.m_c1);
}

}  // namespace Botan::BLS12_381
