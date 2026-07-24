/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLS12_381_TOWER_H_
#define BOTAN_BLS12_381_TOWER_H_

#include <botan/internal/bls12_381_fields.h>

namespace Botan::BLS12_381 {

/**
* An element of Fp6 = Fp2[v]/(v^3 - (u + 1))
*
* Represented as c0 + c1*v + c2*v^2
*/
class BOTAN_TEST_API Fp6 final {
   public:
      // Default zero initialized
      constexpr Fp6() = default;

      constexpr Fp6(const FieldElement2& c0, const FieldElement2& c1, const FieldElement2& c2) :
            m_c0(c0), m_c1(c1), m_c2(c2) {}

      static Fp6 zero() { return Fp6(); }

      static Fp6 one() { return Fp6(FieldElement2::one(), FieldElement2::zero(), FieldElement2::zero()); }

      const FieldElement2& c0() const { return m_c0; }

      const FieldElement2& c1() const { return m_c1; }

      const FieldElement2& c2() const { return m_c2; }

      CT::Choice is_zero() const;

      Fp6 add(const Fp6& x) const;

      Fp6 sub(const Fp6& x) const;

      Fp6 mul(const Fp6& x) const;

      Fp6 square() const;

      Fp6 negate() const;

      /**
      * Return the inverse of this element, or zero for zero
      */
      Fp6 invert() const;

      /**
      * Multiplication by v
      */
      Fp6 mul_by_nonresidue() const;

      /**
      * Sparse multiplication by b1*v
      */
      Fp6 mul_by_1(const FieldElement2& b1) const;

      /**
      * Sparse multiplication by b0 + b1*v
      */
      Fp6 mul_by_01(const FieldElement2& b0, const FieldElement2& b1) const;

      /**
      * The Frobenius endomorphism x -> x^p
      */
      Fp6 frobenius_map() const;

      CT::Choice operator==(const Fp6& other) const;

      void _conditional_assign(CT::Choice cnd, const Fp6& other);

   private:
      FieldElement2 m_c0;
      FieldElement2 m_c1;
      FieldElement2 m_c2;
};

inline Fp6 operator+(const Fp6& a, const Fp6& b) {
   return a.add(b);
}

inline Fp6 operator-(const Fp6& a, const Fp6& b) {
   return a.sub(b);
}

inline Fp6 operator*(const Fp6& a, const Fp6& b) {
   return a.mul(b);
}

/**
* An element of Fp12 = Fp6[w]/(w^2 - v)
*
* Represented as c0 + c1*w
*/
class BOTAN_TEST_API Fp12 final {
   public:
      static constexpr size_t BYTES = 12 * FieldElement::BYTES;

      // Default zero initialized
      constexpr Fp12() = default;

      constexpr Fp12(const Fp6& c0, const Fp6& c1) : m_c0(c0), m_c1(c1) {}

      static Fp12 zero() { return Fp12(); }

      static Fp12 one() { return Fp12(Fp6::one(), Fp6::zero()); }

      const Fp6& c0() const { return m_c0; }

      const Fp6& c1() const { return m_c1; }

      CT::Choice is_zero() const;

      /**
      * Serialization for tests and Gt; the coefficients are encoded in
      * the order c0.c0.c0, c0.c0.c1, c0.c1.c0, ..., c1.c2.c1 with each
      * Fp coefficient as 48 big-endian bytes
      */
      void serialize_to(std::span<uint8_t, Fp12::BYTES> bytes) const;

      std::array<uint8_t, Fp12::BYTES> serialize() const {
         std::array<uint8_t, Fp12::BYTES> buf{};
         this->serialize_to(buf);
         return buf;
      }

      Fp12 add(const Fp12& x) const;

      Fp12 sub(const Fp12& x) const;

      Fp12 mul(const Fp12& x) const;

      Fp12 square() const;

      Fp12 negate() const;

      /**
      * Return the inverse of this element, or zero for zero
      */
      Fp12 invert() const;

      /**
      * Conjugation c0 - c1*w; for elements of the cyclotomic subgroup
      * (such as pairing values) this is the inverse
      */
      Fp12 conjugate() const;

      /**
      * Sparse multiplication by b = (b0 + b1*v)*1 + (b4*v)*w, the shape
      * produced by pairing line evaluations
      */
      Fp12 mul_by_014(const FieldElement2& b0, const FieldElement2& b1, const FieldElement2& b4) const;

      /**
      * The Frobenius endomorphism x -> x^p
      */
      Fp12 frobenius_map() const;

      /**
      * Squaring specialized for elements of the cyclotomic subgroup
      */
      Fp12 cyclotomic_square() const;

      CT::Choice operator==(const Fp12& other) const;

      void _conditional_assign(CT::Choice cnd, const Fp12& other);

   private:
      Fp6 m_c0;
      Fp6 m_c1;
};

inline Fp12 operator+(const Fp12& a, const Fp12& b) {
   return a.add(b);
}

inline Fp12 operator-(const Fp12& a, const Fp12& b) {
   return a.sub(b);
}

inline Fp12 operator*(const Fp12& a, const Fp12& b) {
   return a.mul(b);
}

}  // namespace Botan::BLS12_381

#endif
