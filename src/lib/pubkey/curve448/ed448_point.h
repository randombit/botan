/*
 * Ed448 Point Arithmetic
 * (C) 2024 Jack Lloyd
 *     2024 René Meusel, Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ED448_POINT_H_
#define BOTAN_ED448_POINT_H_

#include <botan/internal/ct_utils.h>
#include <botan/internal/curve448_gf.h>
#include <botan/internal/curve448_scalar.h>

namespace Botan {

constexpr size_t ED448_LEN = 57;

/**
 * @brief Representation of a point on the Ed448 curve.
 *
 * The point is represented in projective coordinates (X, Y, Z).
 * All operations are constant time.
 */
class BOTAN_TEST_API Ed448Point final {
   public:
      /// Decode a point from its 57-byte encoding (RFC 8032 5.2.3)
      static Ed448Point decode(std::span<const uint8_t, ED448_LEN> enc);

      /// Create the curve's base point ('B' in RFC 8032 5.2)
      static Ed448Point base_point();

      /// Create a point from its projective coordinates X, Y, Z
      Ed448Point(const Gf448Elem& x, const Gf448Elem& y, const Gf448Elem& z) : m_x(x), m_y(y), m_z(z) {}

      /// Create a point from its coordinates x, y
      Ed448Point(const Gf448Elem& x, const Gf448Elem& y) : m_x(x), m_y(y), m_z(1) {}

      /// Return the identity element
      static Ed448Point identity() { return Ed448Point(Gf448Elem::zero(), Gf448Elem::one()); }

      /// Return true if this is the identity element
      bool is_identity() const { return m_x.is_zero() && m_y == m_z; }

      /// Encode the point to its 57-byte representation (RFC 8032 5.2.2)
      std::array<uint8_t, ED448_LEN> encode() const;

      /// Add two points (RFC 8032 5.2.4)
      Ed448Point operator+(const Ed448Point& other) const;

      /// Double a point (RFC 8032 5.2.4)
      Ed448Point double_point() const;

      /// Scalar multiplication
      Ed448Point scalar_mul(const Scalar448& scalar) const;

      /// Fixed base point scalar multiplication (precomputed table, no doublings)
      static Ed448Point base_point_mul(const Scalar448& scalar);

      /// Variable-time double scalar multiplication using Shamir's trick: [s1]P + [s2]Q
      static Ed448Point double_scalar_mul_vartime(const Scalar448& s1,
                                                  const Ed448Point& p1,
                                                  const Scalar448& s2,
                                                  const Ed448Point& p2);

      /// Negate the point
      Ed448Point negate() const { return Ed448Point(-m_x, m_y, m_z); }

      /// Getter for projective coordinate X
      Gf448Elem x_proj() const { return m_x; }

      /// Getter for projective coordinate Y
      Gf448Elem y_proj() const { return m_y; }

      /// Getter for projective coordinate Z
      Gf448Elem z_proj() const { return m_z; }

      /// Getter for point coordinate x
      Gf448Elem x() const { return m_x / m_z; }

      /// Getter for point coordinate y
      Gf448Elem y() const { return m_y / m_z; }

      /// Check if two points are equal (constant time)
      bool operator==(const Ed448Point& other) const;

      /// Assign other to this if @p mask is set (constant time)
      void ct_conditional_assign(CT::Mask<uint64_t> mask, const Ed448Point& other);

   private:
      Gf448Elem m_x;
      Gf448Elem m_y;
      Gf448Elem m_z;
};

/// Syntax sugar for scalar multiplication
Ed448Point operator*(const Scalar448& lhs, const Ed448Point& rhs);

}  // namespace Botan

#endif  // BOTAN_ED448_POINT_H_
