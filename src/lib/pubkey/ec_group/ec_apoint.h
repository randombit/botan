/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_APOINT_H_
#define BOTAN_EC_APOINT_H_

#include <botan/concepts.h>
#include <botan/ec_point_format.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace Botan {

class BigInt;
class RandomNumberGenerator;
class EC_Group;
class EC_Scalar;

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
class EC_Point;
#endif

class EC_Group_Data;
class EC_AffinePoint_Data;

/// Elliptic Curve Point in Affine Representation
///
class BOTAN_UNSTABLE_API EC_AffinePoint final {
   public:
      /// Point deserialization. Throws if wrong length or not a valid point
      ///
      /// This accepts SEC1 compressed or uncompressed formats
      EC_AffinePoint(const EC_Group& group, std::span<const uint8_t> bytes);

      /// Point deserialization. Returns nullopt if wrong length or not a valid point
      ///
      /// This accepts SEC1 compressed or uncompressed formats
      static std::optional<EC_AffinePoint> deserialize(const EC_Group& group, std::span<const uint8_t> bytes);

      /// Create a point from a pair (x,y) of integers
      ///
      /// The integers must be within the field - in the range [0,p) and must
      /// satisfy the curve equation
      static std::optional<EC_AffinePoint> from_bigint_xy(const EC_Group& group, const BigInt& x, const BigInt& y);

      /// Multiply by the group generator returning a complete point
      ///
      /// Workspace argument is transitional
      static EC_AffinePoint g_mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws);

      /// Return the identity element
      static EC_AffinePoint identity(const EC_Group& group);

      /// Return the standard group generator
      static EC_AffinePoint generator(const EC_Group& group);

      /// Hash to curve (RFC 9380), random oracle variant
      ///
      /// Only supported for specific groups
      static EC_AffinePoint hash_to_curve_ro(const EC_Group& group,
                                             std::string_view hash_fn,
                                             std::span<const uint8_t> input,
                                             std::span<const uint8_t> domain_sep);

      /// Hash to curve (RFC 9380), non uniform variant
      ///
      /// Only supported for specific groups
      static EC_AffinePoint hash_to_curve_nu(const EC_Group& group,
                                             std::string_view hash_fn,
                                             std::span<const uint8_t> input,
                                             std::span<const uint8_t> domain_sep);

      /// Multiply a point by a scalar returning a complete point
      ///
      /// Workspace argument is transitional
      EC_AffinePoint mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const;

      /// Multiply a point by a scalar, returning the byte encoding of the x coordinate only
      ///
      /// Workspace argument is transitional
      secure_vector<uint8_t> mul_x_only(const EC_Scalar& scalar,
                                        RandomNumberGenerator& rng,
                                        std::vector<BigInt>& ws) const;

      /// Compute 2-ary multiscalar multiplication - p*x + q*y
      ///
      /// This operation runs in constant time with respect to p, x, q, and y
      ///
      /// @returns p*x+q*y, or nullopt if the result was the point at infinity
      static std::optional<EC_AffinePoint> mul_px_qy(const EC_AffinePoint& p,
                                                     const EC_Scalar& x,
                                                     const EC_AffinePoint& q,
                                                     const EC_Scalar& y,
                                                     RandomNumberGenerator& rng);

      /// Point addition
      ///
      /// Note that this is quite slow since it converts the resulting
      /// projective point immediately to affine coordinates, which requires a
      /// field inversion. This can be sufficient when implementing protocols
      /// that just need to perform a few additions.
      ///
      /// In the future a cooresponding EC_ProjectivePoint type may be added
      /// which would avoid the expensive affine conversions
      EC_AffinePoint add(const EC_AffinePoint& q) const;

      /// Point negation
      EC_AffinePoint negate() const;

      /// Return the number of bytes of a field element
      ///
      /// A point consists of two field elements, plus possibly a header
      size_t field_element_bytes() const;

      /// Return true if this point is the identity element
      bool is_identity() const;

      /// Write the fixed length encoding of affine x coordinate
      ///
      /// The output span must be exactly field_element_bytes long
      ///
      /// This function will fail if this point is the identity element
      void serialize_x_to(std::span<uint8_t> bytes) const;

      /// Write the fixed length encoding of affine y coordinate
      ///
      /// The output span must be exactly field_element_bytes long
      ///
      /// This function will fail if this point is the identity element
      void serialize_y_to(std::span<uint8_t> bytes) const;

      /// Write the fixed length encoding of affine x and y coordinates
      ///
      /// The output span must be exactly 2*field_element_bytes long
      ///
      /// This function will fail if this point is the identity element
      void serialize_xy_to(std::span<uint8_t> bytes) const;

      /// Write the fixed length SEC1 compressed encoding
      ///
      /// The output span must be exactly 1 + field_element_bytes long
      ///
      /// This function will fail if this point is the identity element
      void serialize_compressed_to(std::span<uint8_t> bytes) const;

      /// Return the fixed length encoding of SEC1 uncompressed encoding
      ///
      /// The output span must be exactly 1 + 2*field_element_bytes long
      ///
      /// This function will fail if this point is the identity element
      void serialize_uncompressed_to(std::span<uint8_t> bytes) const;

      /// Return the bytes of the affine x coordinate in a container
      ///
      /// This function will fail if this point is the identity element
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T x_bytes() const {
         T bytes(this->field_element_bytes());
         this->serialize_x_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine y coordinate in a container
      ///
      /// This function will fail if this point is the identity element
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T y_bytes() const {
         T bytes(this->field_element_bytes());
         this->serialize_y_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine x and y coordinates in a container
      ///
      /// This function will fail if this point is the identity element
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T xy_bytes() const {
         T bytes(2 * this->field_element_bytes());
         this->serialize_xy_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine x and y coordinates in a container
      ///
      /// This function will fail if this point is the identity element
      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      T serialize_uncompressed() const {
         T bytes(1 + 2 * this->field_element_bytes());
         this->serialize_uncompressed_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine x and y coordinates in a container
      ///
      /// This function will fail if this point is the identity element
      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      T serialize_compressed() const {
         T bytes(1 + this->field_element_bytes());
         this->serialize_compressed_to(bytes);
         return bytes;
      }

      bool operator==(const EC_AffinePoint& other) const;

      bool operator!=(const EC_AffinePoint& other) const { return !(*this == other); }

      /// Return an encoding depending on the requested format
      std::vector<uint8_t> serialize(EC_Point_Format format) const;

      EC_AffinePoint(const EC_AffinePoint& other);
      EC_AffinePoint(EC_AffinePoint&& other) noexcept;

      EC_AffinePoint& operator=(const EC_AffinePoint& other);
      EC_AffinePoint& operator=(EC_AffinePoint&& other) noexcept;

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Deprecated conversion
      */
      EC_AffinePoint(const EC_Group& group, const EC_Point& pt);

      /**
      * Deprecated conversion
      */
      EC_Point to_legacy_point() const;
#endif

      ~EC_AffinePoint();

      const EC_AffinePoint_Data& _inner() const { return inner(); }

      static EC_AffinePoint _from_inner(std::unique_ptr<EC_AffinePoint_Data> inner);

      const std::shared_ptr<const EC_Group_Data>& _group() const;

   private:
      friend class EC_Mul2Table;

      EC_AffinePoint(std::unique_ptr<EC_AffinePoint_Data> point);

      const EC_AffinePoint_Data& inner() const { return *m_point; }

      std::unique_ptr<EC_AffinePoint_Data> m_point;
};

}  // namespace Botan

#endif
