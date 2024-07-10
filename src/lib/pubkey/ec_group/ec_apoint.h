/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_APOINT_H_
#define BOTAN_EC_APOINT_H_

#include <botan/concepts.h>
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
class EC_Point;

class EC_Group_Data;
class EC_AffinePoint_Data;

class BOTAN_UNSTABLE_API EC_AffinePoint final {
   public:
      /// Point deserialization. Returns nullopt if wrong length or not a valid point
      static std::optional<EC_AffinePoint> deserialize(const EC_Group& group, std::span<const uint8_t> bytes);

      /// Multiply by the group generator returning a complete point
      ///
      /// Workspace argument is transitional
      static EC_AffinePoint g_mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws);

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

      /// Return the number of bytes of a field element
      ///
      /// A point consists of two field elements, plus possibly a header
      size_t field_element_bytes() const;

      /// Write the fixed length encoding of affine x coordinate
      ///
      /// The output span must be exactly field_element_bytes long
      void serialize_x_to(std::span<uint8_t> bytes) const;

      /// Write the fixed length encoding of affine y coordinate
      ///
      /// The output span must be exactly field_element_bytes long
      void serialize_y_to(std::span<uint8_t> bytes) const;

      /// Write the fixed length encoding of affine x and y coordinates
      ///
      /// The output span must be exactly 2*field_element_bytes long
      void serialize_xy_to(std::span<uint8_t> bytes) const;

      /// Write the fixed length SEC1 compressed encoding
      ///
      /// The output span must be exactly 1 + field_element_bytes long
      void serialize_compressed_to(std::span<uint8_t> bytes) const;

      /// Return the fixed length encoding of SEC1 uncompressed encoding
      ///
      /// The output span must be exactly 1 + 2*field_element_bytes long
      void serialize_uncompressed_to(std::span<uint8_t> bytes) const;

      /// Return the bytes of the affine x coordinate in a container
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T x_bytes() const {
         T bytes(this->field_element_bytes());
         this->serialize_x_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine y coordinate in a container
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T y_bytes() const {
         T bytes(this->field_element_bytes());
         this->serialize_y_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine x and y coordinates in a container
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T xy_bytes() const {
         T bytes(2 * this->field_element_bytes());
         this->serialize_xy_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine x and y coordinates in a container
      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      T serialize_uncompressed() const {
         T bytes(1 + 2 * this->field_element_bytes());
         this->serialize_uncompressed_to(bytes);
         return bytes;
      }

      /// Return the bytes of the affine x and y coordinates in a container
      template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
      T serialize_compressed() const {
         T bytes(1 + this->field_element_bytes());
         this->serialize_compressed_to(bytes);
         return bytes;
      }

      EC_AffinePoint(const EC_AffinePoint& other);
      EC_AffinePoint(EC_AffinePoint&& other) noexcept;

      EC_AffinePoint& operator=(const EC_AffinePoint& other);
      EC_AffinePoint& operator=(EC_AffinePoint&& other) noexcept;

      EC_AffinePoint(const EC_Group& group, std::span<const uint8_t> bytes);

      /**
      * Deprecated conversion
      */
      EC_AffinePoint(const EC_Group& group, const EC_Point& pt);

      /**
      * Deprecated conversion
      */
      EC_Point to_legacy_point() const;

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
