/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLS12_381_H_
#define BOTAN_BLS12_381_H_

#include <botan/types.h>
#include <array>
#include <optional>
#include <span>
#include <vector>

namespace Botan::BLS12_381 {

// The field element and extension tower types are internal; functions
// naming these types are reserved for internal use and not covered by SemVer
class FieldElement;
class FieldElement2;
class Fp12;

/**
* A BLS12-381 scalar
*
* Integer modulo 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
*/
class BOTAN_PUBLIC_API(3, 13) Scalar final {
   public:
      static constexpr size_t BITS = 255;
      static constexpr size_t BYTES = (BITS + 7) / 8;
      static constexpr size_t N = (BYTES + sizeof(word) - 1) / sizeof(word);

      static_assert(BYTES == N * sizeof(word));

      // Default zero initialized
      constexpr Scalar() : m_val({}) {}

      Scalar(const Scalar& other) = default;
      Scalar& operator=(const Scalar& other) = default;

      /**
      * Scalars are commonly secrets, so they are zeroized on
      * destruction, and moving from a Scalar zeroizes the source
      */
      Scalar(Scalar&& other) noexcept : m_val(other.m_val) { other.wipe(); }

      Scalar& operator=(Scalar&& other) noexcept {
         if(this != &other) {
            m_val = other.m_val;
            other.wipe();
         }
         return *this;
      }

      ~Scalar() { this->wipe(); }

      static Scalar from_u32(uint32_t v);

      static Scalar zero() { return Scalar(); }

      static Scalar one();

      /**
      * Deserialize a scalar from a 32-byte long big-endian encoding
      *
      * Returns nullopt unless the encoding is a canonical integer in the
      * range [1, r). In particular the zero scalar is rejected, since a zero
      * scalar is almost always a mistake; this matches EC_Scalar::deserialize.
      *
      * @note that some implementations of BLS12-381 use little-endian scalar encodings
      */
      static std::optional<Scalar> deserialize(std::span<const uint8_t> bytes);

      static Scalar from_bytes_wide(std::span<const uint8_t, 64> bytes);

      /**
      * Hash an input to a scalar
      *
      * Uses the hash_to_field construction of RFC 9380, namely expand_message_xmd with
      * SHA-256 followed by wide reduction. The distribution of the result is uniform
      * (negligibly biased). The domain separation tag dst distinguishes different uses
      * of the hash; see RFC 9380 section 3.1 for the requirements.
      */
      static Scalar hash(std::span<const uint8_t> input, std::span<const uint8_t> dst);

      void serialize_to(std::span<uint8_t, Scalar::BYTES> bytes) const;

      std::array<uint8_t, Scalar::BYTES> serialize() const {
         std::array<uint8_t, Scalar::BYTES> buf{};
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

   private:
      // Squaring in place
      void square_n(size_t n);

      void wipe();

      constexpr const std::array<word, N>& value() const { return m_val; }

      constexpr const word* data() const { return m_val.data(); }

      static Scalar from_words(std::array<word, Scalar::N> v);

      explicit constexpr Scalar(std::array<word, Scalar::N> v) : m_val(v) {}

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

class BOTAN_PUBLIC_API(3, 13) G1Affine final {
   public:
      static constexpr size_t BYTES = 48;

      /**
      * Return the G1 identity element
      */
      static G1Affine identity();

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
      * Check if this point is the identity element
      */
      bool is_identity() const;

      /**
      * Access the coordinates directly; the values are meaningless if
      * the point is the identity element.
      *
      * Reserved for internal use, not covered by SemVer.
      */
      FieldElement _x() const;
      FieldElement _y() const;

   private:
      friend class G1Projective;

      G1Affine(const FieldElement& x, const FieldElement& y, uint32_t infinity);

      static constexpr size_t FE_WORDS = 48 / sizeof(word);

      std::array<word, FE_WORDS> m_x;
      std::array<word, FE_WORDS> m_y;
      uint32_t m_infinity;
};

class BOTAN_PUBLIC_API(3, 13) G1Projective final {
   public:
      /**
      * Default constructed as the identity element
      */
      G1Projective();

      static G1Projective from_affine(const G1Affine& affine);

      static G1Projective identity() { return G1Projective(); }

      static G1Projective generator();

      G1Affine to_affine() const;

      G1Projective negate() const;

      G1Projective add(const G1Projective& other) const;

      G1Projective add_mixed(const G1Affine& other) const;

      G1Projective mul(const Scalar& scalar) const;

      /**
      * Compute a*p + b*q in constant time
      *
      * Faster than composing mul() and add(), and safe for secret
      * scalars, as arise for example in Pedersen commitments.
      */
      static G1Projective mul2(const G1Projective& p, const Scalar& a, const G1Projective& q, const Scalar& b);

      /**
      * Compute a*p + b*q
      *
      * Warning: this function runs in variable time and must be used
      * only with public inputs, such as signature verification. Use
      * mul2() with secret scalars.
      */
      static G1Projective mul2_vartime(const G1Projective& p, const Scalar& a, const G1Projective& q, const Scalar& b);

      /**
      * Check if this point is the identity element
      */
      bool is_identity() const;

      /**
      * Hash to curve (RFC 9380), suite BLS12381G1_XMD:SHA-256_SSWU_RO_
      */
      static G1Projective hash_to_curve_ro(std::span<const uint8_t> input, std::span<const uint8_t> dst);

      /**
      * Nonuniform encoding to curve (RFC 9380 encode_to_curve),
      * suite BLS12381G1_XMD:SHA-256_SSWU_NU_
      */
      static G1Projective hash_to_curve_nu(std::span<const uint8_t> input, std::span<const uint8_t> dst);

      /**
      * Multiscalar multiplication, the sum of scalars[i]*points[i]
      *
      * The empty sum is the identity element. Throws Invalid_Argument
      * if the spans are of unequal length.
      *
      * Warning: this function runs in variable time and must be used
      * only with public inputs, such as signature verification. Use
      * mul() with secret scalars.
      */
      static G1Projective msm_vartime(std::span<const G1Affine> points, std::span<const Scalar> scalars);

      /**
      * Convert a batch of points to affine
      *
      * Equivalent to calling to_affine on each point, but much faster,
      * since a single field inversion is shared across the batch.
      */
      static std::vector<G1Affine> to_affine_batch(std::span<const G1Projective> points);

      /**
      * The input is assumed to be a point on the curve, though possibly
      * outside the prime order subgroup.
      *
      * Reserved for internal use, not covered by SemVer.
      */
      static G1Projective _unchecked_from_affine_coords(const FieldElement& x, const FieldElement& y);

   private:
      G1Projective(const FieldElement& x, const FieldElement& y, const FieldElement& z);

      G1Projective dbl() const;

      friend class G1Affine;

      template <typename Pt>
      friend class PointMul;

      static constexpr size_t FE_WORDS = 48 / sizeof(word);

      std::array<word, FE_WORDS> m_x;
      std::array<word, FE_WORDS> m_y;
      std::array<word, FE_WORDS> m_z;
};

class BOTAN_PUBLIC_API(3, 13) G2Affine final {
   public:
      static constexpr size_t BYTES = 96;

      /**
      * Return the G2 identity element
      */
      static G2Affine identity();

      /**
      * Return the G2 standard group generator
      */
      static G2Affine generator();

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
      * Check if this point is the identity element
      */
      bool is_identity() const;

      /**
      * Access the coordinates directly; the values are meaningless if
      * the point is the identity element.
      *
      * Reserved for internal use, not covered by SemVer.
      */
      FieldElement2 _x() const;
      FieldElement2 _y() const;

   private:
      friend class G2Projective;

      G2Affine(const FieldElement2& x, const FieldElement2& y, uint32_t infinity);

      static constexpr size_t FE2_WORDS = 96 / sizeof(word);

      std::array<word, FE2_WORDS> m_x;
      std::array<word, FE2_WORDS> m_y;
      uint32_t m_infinity;
};

class BOTAN_PUBLIC_API(3, 13) G2Projective final {
   public:
      /**
      * Default constructed as the identity element
      */
      G2Projective();

      static G2Projective from_affine(const G2Affine& affine);

      static G2Projective identity() { return G2Projective(); }

      static G2Projective generator();

      G2Affine to_affine() const;

      G2Projective negate() const;

      G2Projective add(const G2Projective& other) const;

      G2Projective add_mixed(const G2Affine& other) const;

      G2Projective mul(const Scalar& scalar) const;

      /**
      * Compute a*p + b*q in constant time
      *
      * Faster than composing mul() and add(), and safe for secret
      * scalars, as arise for example in Pedersen commitments.
      */
      static G2Projective mul2(const G2Projective& p, const Scalar& a, const G2Projective& q, const Scalar& b);

      /**
      * Compute a*p + b*q
      *
      * Warning: this function runs in variable time and must be used
      * only with public inputs, such as signature verification. Use
      * mul2() with secret scalars.
      */
      static G2Projective mul2_vartime(const G2Projective& p, const Scalar& a, const G2Projective& q, const Scalar& b);

      /**
      * Check if this point is the identity element
      */
      bool is_identity() const;

      /**
      * Hash to curve (RFC 9380), suite BLS12381G2_XMD:SHA-256_SSWU_RO_
      */
      static G2Projective hash_to_curve_ro(std::span<const uint8_t> input, std::span<const uint8_t> dst);

      /**
      * Nonuniform encoding to curve (RFC 9380 encode_to_curve),
      * suite BLS12381G2_XMD:SHA-256_SSWU_NU_
      */
      static G2Projective hash_to_curve_nu(std::span<const uint8_t> input, std::span<const uint8_t> dst);

      /**
      * Multiscalar multiplication, the sum of scalars[i]*points[i]
      *
      * The empty sum is the identity element. Throws Invalid_Argument
      * if the spans are of unequal length.
      *
      * Warning: this function runs in variable time and must be used
      * only with public inputs, such as signature verification. Use
      * mul() with secret scalars.
      */
      static G2Projective msm_vartime(std::span<const G2Affine> points, std::span<const Scalar> scalars);

      /**
      * Convert a batch of points to affine
      *
      * Equivalent to calling to_affine on each point, but much faster,
      * since a single field inversion is shared across the batch.
      */
      static std::vector<G2Affine> to_affine_batch(std::span<const G2Projective> points);

      /**
      * The input is assumed to be a point on the curve, though possibly
      * outside the prime order subgroup.
      *
      * Reserved for internal use, not covered by SemVer.
      */
      static G2Projective _unchecked_from_affine_coords(const FieldElement2& x, const FieldElement2& y);

   private:
      G2Projective(const FieldElement2& x, const FieldElement2& y, const FieldElement2& z);

      G2Projective dbl() const;

      /**
      * The untwist-Frobenius-twist endomorphism, and its square
      */
      G2Projective psi() const;
      G2Projective psi2() const;

      /**
      * Cofactor clearing for hash to curve
      */
      G2Projective clear_cofactor() const;

      friend class G2Affine;

      template <typename Pt>
      friend class PointMul;

      static constexpr size_t FE2_WORDS = 96 / sizeof(word);

      std::array<word, FE2_WORDS> m_x;
      std::array<word, FE2_WORDS> m_y;
      std::array<word, FE2_WORDS> m_z;
};

/**
* An element of the pairing target group, a subgroup of Fp12*
*
* Elements are members of the prime order subgroup by construction;
* there is no deserialization.
*/
class BOTAN_PUBLIC_API(3, 13) Gt final {
   public:
      static constexpr size_t BYTES = 576;

      /**
      * Compute the optimal ate pairing e(p, q)
      */
      static Gt pairing(const G1Affine& p, const G2Affine& q);

      /**
      * Compute the product of pairings prod_i e(p[i], q[i])
      *
      * More efficient than multiplying individual pairings, since the final
      * exponentiation is shared. The empty product yields the identity.
      *
      * Throws Invalid_Argument if the spans are of unequal length.
      */
      static Gt multi_pairing(std::span<const G1Affine> p, std::span<const G2Affine> q);

      /**
      * Return the Gt identity element
      */
      static Gt identity();

      /**
      * Check if this element is the identity
      */
      bool is_identity() const;

      /**
      * Constant time equality
      */
      bool operator==(const Gt& other) const;

      /**
      * Serialization of the underlying Fp12 element; the coefficients
      * are encoded in the order c0.c0.c0, c0.c0.c1, ..., c1.c2.c1 with
      * each Fp coefficient as 48 big-endian bytes
      */
      std::array<uint8_t, BYTES> serialize() const;

   private:
      explicit Gt(const Fp12& v);

      Fp12 _to_fp12() const;

      static constexpr size_t WORDS = 12 * (48 / sizeof(word));

      std::array<word, WORDS> m_coeffs;
};

}  // namespace Botan::BLS12_381

#endif
