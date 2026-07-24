/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLS12_381_FIELDS_H_
#define BOTAN_BLS12_381_FIELDS_H_

#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <array>
#include <optional>
#include <span>

namespace Botan::BLS12_381 {

/**
* A BLS12-381 field element
*
* Integer modulo 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
*/
class BOTAN_TEST_API FieldElement final {
   public:
      static constexpr size_t BITS = 381;
      static constexpr size_t BYTES = (BITS + 7) / 8;
      static constexpr size_t N = (BYTES + sizeof(word) - 1) / sizeof(word);

      static_assert(BYTES == N * sizeof(word));

      // Default zero initialized
      constexpr FieldElement() : m_val({}) {}

      static FieldElement from_u32(uint32_t v);

      static FieldElement zero() { return FieldElement(); }

      static FieldElement one();

      static std::optional<FieldElement> deserialize(std::span<const uint8_t> bytes);

      static FieldElement from_bytes_wide(std::span<const uint8_t, 96> bytes);

      CT::Choice is_zero() const;

      void serialize_to(std::span<uint8_t, FieldElement::BYTES> bytes) const;

      std::array<uint8_t, FieldElement::BYTES> serialize() const {
         std::array<uint8_t, FieldElement::BYTES> buf{};
         this->serialize_to(buf);
         return buf;
      }

      FieldElement add(const FieldElement& x) const;

      FieldElement sub(const FieldElement& x) const;

      FieldElement mul(const FieldElement& x) const;

      FieldElement& operator+=(const FieldElement& x) {
         (*this) = this->add(x);
         return (*this);
      }

      FieldElement& operator-=(const FieldElement& x) {
         (*this) = this->sub(x);
         return (*this);
      }

      FieldElement& operator*=(const FieldElement& x) {
         (*this) = this->mul(x);
         return (*this);
      }

      FieldElement negate() const;

      FieldElement invert() const;

      FieldElement square() const;

      /**
      * Return the square root of this element, if one exists
      *
      * If x and -x are both square roots, which of the two is returned
      * is unspecified.
      */
      std::optional<FieldElement> sqrt() const;

      /**
      * Constant time equality
      */
      CT::Choice operator==(const FieldElement& other) const;

      CT::Choice operator!=(const FieldElement& other) const { return !(*this == other); }

      /**
      * Set iff this is larger than its negation
      *
      * Ie set if this is > (p-1)/2
      */
      CT::Choice _is_lexicographically_largest() const;

      /**
      * The input is assumed to be valid and already in Montgomery representation
      */
      static constexpr FieldElement _unchecked_from_words(std::array<word, FieldElement::N> v) {
         return FieldElement(v);
      }

      /**
      * The Montgomery representation words
      */
      constexpr const std::array<word, N>& _words() const { return m_val; }

      /**
      * If cnd is set assign other to this, in constant time
      */
      void _conditional_assign(CT::Choice cnd, const FieldElement& other);

   private:
      // Squaring in place
      void square_n(size_t n);

      constexpr const std::array<word, N>& value() const { return m_val; }

      constexpr const word* data() const { return m_val.data(); }

      static FieldElement from_words(std::array<word, FieldElement::N> v);

      explicit constexpr FieldElement(std::array<word, FieldElement::N> v) : m_val(v) {}

      std::array<word, FieldElement::N> m_val;
};

inline FieldElement operator+(const FieldElement& a, const FieldElement& b) {
   return a.add(b);
}

inline FieldElement operator-(const FieldElement& a, const FieldElement& b) {
   return a.sub(b);
}

inline FieldElement operator*(const FieldElement& a, const FieldElement& b) {
   return a.mul(b);
}

/**
* An element of the extension field Fp2 = Fp[u]/(u^2 + 1)
*
* Represented as c0 + c1*u
*/
class BOTAN_TEST_API FieldElement2 final {
   public:
      static constexpr size_t BYTES = 2 * FieldElement::BYTES;

      // Default zero initialized
      constexpr FieldElement2() = default;

      constexpr FieldElement2(const FieldElement& c0, const FieldElement& c1) : m_c0(c0), m_c1(c1) {}

      static FieldElement2 zero() { return FieldElement2(); }

      static FieldElement2 one() { return FieldElement2(FieldElement::one(), FieldElement::zero()); }

      /**
      * Deserialization; the c1 coefficient is encoded first, following
      * the ZCash convention for G2 point encoding
      */
      static std::optional<FieldElement2> deserialize(std::span<const uint8_t> bytes);

      void serialize_to(std::span<uint8_t, FieldElement2::BYTES> bytes) const;

      std::array<uint8_t, FieldElement2::BYTES> serialize() const {
         std::array<uint8_t, FieldElement2::BYTES> buf{};
         this->serialize_to(buf);
         return buf;
      }

      const FieldElement& c0() const { return m_c0; }

      const FieldElement& c1() const { return m_c1; }

      CT::Choice is_zero() const;

      FieldElement2 add(const FieldElement2& x) const;

      FieldElement2 sub(const FieldElement2& x) const;

      FieldElement2 mul(const FieldElement2& x) const;

      FieldElement2& operator+=(const FieldElement2& x) {
         (*this) = this->add(x);
         return (*this);
      }

      FieldElement2& operator-=(const FieldElement2& x) {
         (*this) = this->sub(x);
         return (*this);
      }

      FieldElement2& operator*=(const FieldElement2& x) {
         (*this) = this->mul(x);
         return (*this);
      }

      FieldElement2 negate() const;

      FieldElement2 invert() const;

      FieldElement2 square() const;

      /**
      * Return the conjugate c0 - c1*u, which is also the image of this
      * element under the Frobenius endomorphism x -> x^p
      */
      FieldElement2 conjugate() const;

      /**
      * Multiplication by the sextic nonresidue u + 1
      */
      FieldElement2 mul_by_nonresidue() const;

      /**
      * Return the square root of this element, if one exists
      *
      * If x and -x are both square roots, which of the two is returned
      * is unspecified.
      */
      std::optional<FieldElement2> sqrt() const;

      /**
      * Constant time equality
      */
      CT::Choice operator==(const FieldElement2& other) const;

      CT::Choice operator!=(const FieldElement2& other) const { return !(*this == other); }

      /**
      * Set iff this is larger than its negation
      *
      * The comparison is lexicographic on (c1, c0), matching the ZCash
      * convention: c1 > (p-1)/2, or c1 == 0 and c0 > (p-1)/2.
      */
      CT::Choice _is_lexicographically_largest() const;

      /**
      * The inputs are assumed to be valid and already in Montgomery representation
      */
      static constexpr FieldElement2 _unchecked_from_words(std::array<word, FieldElement::N> c0,
                                                           std::array<word, FieldElement::N> c1) {
         return FieldElement2(FieldElement::_unchecked_from_words(c0), FieldElement::_unchecked_from_words(c1));
      }

      /**
      * If cnd is set assign other to this, in constant time
      */
      void _conditional_assign(CT::Choice cnd, const FieldElement2& other);

   private:
      FieldElement m_c0;
      FieldElement m_c1;
};

inline FieldElement2 operator+(const FieldElement2& a, const FieldElement2& b) {
   return a.add(b);
}

inline FieldElement2 operator-(const FieldElement2& a, const FieldElement2& b) {
   return a.sub(b);
}

inline FieldElement2 operator*(const FieldElement2& a, const FieldElement2& b) {
   return a.mul(b);
}

}  // namespace Botan::BLS12_381

#endif
