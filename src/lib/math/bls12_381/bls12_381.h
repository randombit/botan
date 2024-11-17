/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLS12_381_H_
#define BOTAN_BLS12_381_H_

#include <botan/types.h>
#include <optional>
#include <span>
#include <vector>

namespace Botan::BLS12_381 {

/**
* A BLS12-381 scalar
*
* Integer modulo 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
*/
class BOTAN_PUBLIC_API(3, 9) Scalar final {
   public:
      static constexpr size_t BITS = 255;
      static constexpr size_t BYTES = (BITS + 7) / 8;
      static constexpr size_t N = (BYTES + sizeof(word) - 1) / sizeof(word);

      static_assert(BYTES == N * sizeof(word));

      // Default zero initialized
      constexpr Scalar() : m_val({}) {}

      static Scalar from_u32(uint32_t v);

      static Scalar zero() { return Scalar(); }

      static Scalar one();

      static std::optional<Scalar> deserialize(std::span<const uint8_t> bytes);

      static Scalar from_bytes_wide(std::span<const uint8_t, 64> bytes);

      void serialize_to(std::span<uint8_t, Scalar::BYTES> bytes) const;

      std::array<uint8_t, Scalar::BYTES> serialize() const {
         std::array<uint8_t, Scalar::BYTES> buf;
         this->serialize_to(buf);
         return buf;
      }

      Scalar add(const Scalar& x) const;

      Scalar sub(const Scalar& x) const;

      Scalar mul(const Scalar& x) const;

      Scalar& operator+=(const Scalar& x) {
         (*this) = this->add(x);
         return (*this);
      }

      Scalar& operator-=(const Scalar& x) {
         (*this) = this->sub(x);
         return (*this);
      }

      Scalar& operator*=(const Scalar& x) {
         (*this) = this->mul(x);
         return (*this);
      }

      Scalar negate() const;

      Scalar invert() const;

      Scalar square() const;

      ~Scalar() = default;

   private:
      // Squaring in place
      void square_n(size_t n);

      constexpr const std::array<word, N>& value() const { return m_val; }

      constexpr const word* data() const { return m_val.data(); }

      static Scalar from_words(std::array<word, Scalar::N> v);

      constexpr Scalar(std::array<word, Scalar::N> v) : m_val(v) {}

      std::array<word, Scalar::N> m_val;
};

inline Scalar operator+(const Scalar& a, const Scalar& b) {
   return a.add(b);
}

inline Scalar operator-(const Scalar& a, const Scalar& b) {
   return a.sub(b);
}

inline Scalar operator*(const Scalar& a, const Scalar& b) {
   return a.mul(b);
}

/**
* A BLS12-381 field element
*
* Integer modulo 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
*/
class BOTAN_PUBLIC_API(3, 9) FieldElement final {
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

      void serialize_to(std::span<uint8_t, FieldElement::BYTES> bytes) const;

      std::array<uint8_t, FieldElement::BYTES> serialize() const {
         std::array<uint8_t, FieldElement::BYTES> buf;
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

      ~FieldElement() = default;

      /**
      * Returns true iff this is larger than its negation
      *
      * Ie returns true if this is >= (p-1)/2
      *
      * Reserved for internal use, not covered by SemVer.
      */
      bool _is_lexicographically_largest() const;

      /**
      * The input is assumed to be valid and already in Montgomery representation
      *
      * Reserved for internal use, not covered by SemVer.
      */
      static constexpr FieldElement _unchecked_from_words(std::array<word, FieldElement::N> v) {
         return FieldElement(v);
      }

   private:
      // Squaring in place
      void square_n(size_t n);

      constexpr const std::array<word, N>& value() const { return m_val; }

      constexpr const word* data() const { return m_val.data(); }

      static FieldElement from_words(std::array<word, FieldElement::N> v);

      constexpr FieldElement(std::array<word, FieldElement::N> v) : m_val(v) {}

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

class BOTAN_PUBLIC_API(3, 9) G1Affine final {
   public:
      static constexpr size_t BYTES = 48;

      /**
      * Return the G1 identity element
      */
      static G1Affine identity() { return G1Affine(FieldElement::zero(), FieldElement::one(), 1); }

      /**
      * Return the G1 standard group generator
      */
      static G1Affine generator();

      /**
      * Point deserialization
      *
      * Only compressed point encoding is supported.
      *
      * This rejects points not in the prime order subgroup.
      */
      static std::optional<G1Affine> deserialize(std::span<const uint8_t> bytes);

      /**
      * Point serialization
      *
      * Only compressed point encoding is supported.
      */
      std::array<uint8_t, G1Affine::BYTES> serialize() const;

      /**
      * Access x coordinate directly
      *
      * This value is meaningless if the point is the identity element
      */
      const FieldElement& x() const { return m_x; }

      /**
      * Access y coordinate directly
      *
      * This value is meaningless if the point is the identity element
      */
      const FieldElement& y() const { return m_y; }

      /**
      * Check if this point is the identity element
      */
      bool is_identity() const;

   private:
      G1Affine(FieldElement x, FieldElement y, uint32_t infinity) : m_x(x), m_y(y), m_infinity(infinity) {}

      FieldElement m_x;
      FieldElement m_y;
      uint32_t m_infinity;
};

class BOTAN_PUBLIC_API(3, 9) G1Projective final {
   public:
      static G1Projective from_affine(const G1Affine& affine) {
         return G1Projective(affine.x(), affine.y(), FieldElement::one(), affine.is_identity());
      }

      static G1Projective identity() {
         return G1Projective(FieldElement::zero(), FieldElement::one(), FieldElement::one(), 1);
      }

      static G1Projective generator();

      G1Affine to_affine() const;

      G1Projective negate() const;

      G1Projective add(const G1Projective& other) const;

      G1Projective add_mixed(const G1Affine& other) const;

      G1Projective mul(const Scalar& scalar) const;

      // TODO
      // std::vector<G1Affine> batch_to_affine(std::span<const G1Projective> points);

      // TODO multiscalar multiplications

      // TODO hash to curve

   private:
      G1Projective(FieldElement x, FieldElement y, FieldElement z, uint32_t infinity) :
            m_x(x), m_y(y), m_z(z), m_infinity(infinity) {}

      G1Projective dbl() const;

      FieldElement m_x;
      FieldElement m_y;
      FieldElement m_z;
      uint32_t m_infinity;
};

#if 0

class BOTAN_TEST_API FieldElement2 {

};

class BOTAN_PUBLIC_API(3,9) G2Affine final {
   public:
      static constexpr size_t BYTES = 48;

      /**
      * Return the G2 identity element
      */
      static G2Affine identity() {
         return G2Affine(FieldElement::zero(), FieldElement::one(), 1);
      }

      /**
      * Return the G2 standard group generator
      */
      static G2Affine generator();

      /**
      * Check if this point is the identity element
      */
      bool is_identity() const;

      /**
      * Point deserialization
      *
      * Only compressed point encoding is supported.
      *
      * This rejects points not in the prime order subgroup.
      */
      static std::optional<G2Affine> deserialize(std::span<const uint8_t> bytes);

      /**
      * Point serialization
      *
      * Only compressed point encoding is supported.
      */
      std::array<uint8_t, G2Affine::BYTES> serialize() const;

      /**
      * Access x coordinate directly
      *
      * This value is meaningless if the point is the identity element
      */
      const FieldElement& x() const { return m_x; }

      /**
      * Access y coordinate directly
      *
      * This value is meaningless if the point is the identity element
      */
      const FieldElement& y() const { return m_y; }
   private:
      G2Affine(FieldElement x, FieldElement y, uint32_t infinity) :
         m_x(x), m_y(y), m_infinity(infinity) {}

      FieldElement m_x;
      FieldElement m_y;
      uint32_t m_infinity;
};

class BOTAN_PUBLIC_API(3,9) G2Projective final {
   public:
      static G2Projective from_affine(const G2Affine& affine) {
         return G2Projective(affine.x(), affine.y(), FieldElement::one(), affine.is_identity());
      }

      static G2Projective identity() {
         return G2Projective(FieldElement::zero(), FieldElement::one(), FieldElement::one(), 1);
      }

      static G2Projective generator();

      G2Affine to_affine() const;

      G2Projective negate() const;

      G2Projective add(const G2Projective& other) const;

      G2Projective add_mixed(const G2Affine& other) const;

      G2Projective mul(const Scalar& scalar) const;

      // TODO
      // std::vector<G2Affine> batch_to_affine(std::span<const G2Projective> points);

      // TODO multiscalar multiplications

      // TODO hash to curve
   private:
      G2Projective(FieldElement x, FieldElement y, FieldElement z, uint32_t infinity) :
         m_x(x), m_y(y), m_z(z), m_infinity(infinity) {}

      G2Projective dbl() const;

      FieldElement m_x;
      FieldElement m_y;
      FieldElement m_z;
      uint32_t m_infinity;
};


class BOTAN_PUBLIC_API(3,9) Gt final {
   public:
      static Gt pairing(const G1Affine& g1, const G2Affine& g2);
};
#endif

}  // namespace Botan::BLS12_381

#endif
