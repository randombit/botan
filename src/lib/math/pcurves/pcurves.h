/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_H_
#define BOTAN_PCURVES_H_

#include <botan/internal/pcurves_id.h>

#include <botan/concepts.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <array>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

}  // namespace Botan

namespace Botan::PCurve {

/**
* An elliptic curve without cofactor in Weierstrass form
*/
class BOTAN_TEST_API PrimeOrderCurve {
   public:
      /// Somewhat arbitrary maximum size for a field or scalar
      ///
      /// Sized to fit at least P-521
      static const size_t MaximumBitLength = 521;

      static const size_t MaximumByteLength = (MaximumBitLength + 7) / 8;

      /// Number of words used to store MaximumByteLength
      static const size_t StorageWords = (MaximumByteLength + sizeof(word) - 1) / sizeof(word);

      static std::shared_ptr<const PrimeOrderCurve> from_name(std::string_view name) {
         if(auto id = PrimeOrderCurveId::from_string(name)) {
            return PrimeOrderCurve::from_id(id.value());
         } else {
            return {};
         }
      }

      static std::shared_ptr<const PrimeOrderCurve> from_id(PrimeOrderCurveId id);

      typedef std::array<word, StorageWords> StorageUnit;
      typedef std::shared_ptr<const PrimeOrderCurve> CurvePtr;

      /// Elliptic curve scalar
      ///
      /// This refers to the set of integers modulo the (prime) group order
      /// of the elliptic curve.
      class Scalar final {
         public:
            Scalar(const Scalar& other) = default;
            Scalar(Scalar&& other) = default;
            Scalar& operator=(const Scalar& other) = default;
            Scalar& operator=(Scalar&& other) = default;
            ~Scalar() = default;

            /**
            * Return the size of the byte encoding of Scalars
            */
            size_t bytes() const { return m_curve->scalar_bytes(); }

            /**
            * Return the fixed length serialization of this scalar
            */
            template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
            T serialize() const {
               T bytes(this->bytes());
               m_curve->serialize_scalar(bytes, *this);
               return bytes;
            }

            /**
            * Perform integer multiplication modulo the group order
            */
            friend Scalar operator*(const Scalar& a, const Scalar& b) { return a.m_curve->scalar_mul(a, b); }

            /**
            * Perform integer addition modulo the group order
            */
            friend Scalar operator+(const Scalar& a, const Scalar& b) { return a.m_curve->scalar_add(a, b); }

            /**
            * Perform integer subtraction modulo the group order
            */
            friend Scalar operator-(const Scalar& a, const Scalar& b) { return a.m_curve->scalar_sub(a, b); }

            /**
            * Check for equality
            */
            friend bool operator==(const Scalar& a, const Scalar& b) { return a.m_curve->scalar_equal(a, b); }

            /**
            * Negate modulo the group order (ie return p - *this where p is the group order)
            */
            Scalar negate() const { return m_curve->scalar_negate(*this); }

            /**
            * Square modulo the group order
            */
            Scalar square() const { return m_curve->scalar_square(*this); }

            /**
            * Return the modular inverse of *this
            *
            * If *this is zero then returns zero.
            */
            Scalar invert() const { return m_curve->scalar_invert(*this); }

            /**
            * Returns true if this is equal to zero
            */
            bool is_zero() const { return m_curve->scalar_is_zero(*this); }

            const auto& _curve() const { return m_curve; }

            const auto& _value() const { return m_value; }

            static Scalar _create(CurvePtr curve, StorageUnit v) { return Scalar(std::move(curve), v); }

         private:
            Scalar(CurvePtr curve, StorageUnit v) : m_curve(std::move(curve)), m_value(v) {}

            CurvePtr m_curve;
            StorageUnit m_value;
      };

      /**
      * A point on the elliptic curve in affine form
      *
      * These points can be serialized, or converted to projective form for computation
      */
      class AffinePoint final {
         public:
            AffinePoint(const AffinePoint& other) = default;
            AffinePoint(AffinePoint&& other) = default;
            AffinePoint& operator=(const AffinePoint& other) = default;
            AffinePoint& operator=(AffinePoint&& other) = default;
            ~AffinePoint() = default;

            static AffinePoint generator(CurvePtr curve) { return curve->generator(); }

            /**
            * Return the size of the uncompressed encoding of points
            */
            size_t bytes() const { return 1 + 2 * m_curve->field_element_bytes(); }

            /**
            * Return the size of the compressed encoding of points
            */
            size_t compressed_bytes() const { return 1 + m_curve->field_element_bytes(); }

            /**
            * Return the serialization of the point in uncompressed form
            */
            template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
            T serialize() const {
               T bytes(this->bytes());
               m_curve->serialize_point(bytes, *this);
               return bytes;
            }

            /**
            * Return the serialization of the point in compressed form
            */
            template <concepts::resizable_byte_buffer T = std::vector<uint8_t>>
            T serialize_compressed() const {
               T bytes(this->compressed_bytes());
               m_curve->serialize_point_compressed(bytes, *this);
               return bytes;
            }

            /**
            * Return the serialization of the x coordinate
            */
            template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
            T x_bytes() const {
               secure_vector<uint8_t> bytes(m_curve->field_element_bytes());
               m_curve->serialize_point_x(bytes, *this);
               return bytes;
            }

            /**
            * Return true if this is the curve identity element (aka the point at infinity)
            */
            bool is_identity() const { return m_curve->affine_point_is_identity(*this); }

            const auto& _curve() const { return m_curve; }

            const auto& _x() const { return m_x; }

            const auto& _y() const { return m_y; }

            static AffinePoint _create(CurvePtr curve, StorageUnit x, StorageUnit y) {
               return AffinePoint(std::move(curve), x, y);
            }

         private:
            AffinePoint(CurvePtr curve, StorageUnit x, StorageUnit y) : m_curve(std::move(curve)), m_x(x), m_y(y) {}

            CurvePtr m_curve;
            StorageUnit m_x;
            StorageUnit m_y;
      };

      /**
      * A point on the elliptic curve in projective form
      *
      * This is a form that is convenient for computation; it must be converted to
      * affine form for comparisons or serialization.
      */
      class ProjectivePoint final {
         public:
            ProjectivePoint(const ProjectivePoint& other) = default;
            ProjectivePoint(ProjectivePoint&& other) = default;
            ProjectivePoint& operator=(const ProjectivePoint& other) = default;
            ProjectivePoint& operator=(ProjectivePoint&& other) = default;
            ~ProjectivePoint() = default;

            /**
            * Convert a point from affine to projective form
            */
            static ProjectivePoint from_affine(const AffinePoint& pt) { return pt._curve()->point_to_projective(pt); }

            /**
            * Convert a point from projective to affine form
            *
            * This operation is expensive; perform it only when required for
            * serialization
            */
            AffinePoint to_affine() const { return m_curve->point_to_affine(*this); }

            ProjectivePoint dbl() const { return m_curve->point_double(*this); }

            ProjectivePoint negate() const { return m_curve->point_negate(*this); }

            friend ProjectivePoint operator+(const ProjectivePoint& x, const ProjectivePoint& y) {
               return x.m_curve->point_add(x, y);
            }

            friend ProjectivePoint operator+(const ProjectivePoint& x, const AffinePoint& y) {
               return x.m_curve->point_add_mixed(x, y);
            }

            const auto& _curve() const { return m_curve; }

            const auto& _x() const { return m_x; }

            const auto& _y() const { return m_y; }

            const auto& _z() const { return m_z; }

            static ProjectivePoint _create(CurvePtr curve, StorageUnit x, StorageUnit y, StorageUnit z) {
               return ProjectivePoint(std::move(curve), x, y, z);
            }

         private:
            ProjectivePoint(CurvePtr curve, StorageUnit x, StorageUnit y, StorageUnit z) :
                  m_curve(std::move(curve)), m_x(x), m_y(y), m_z(z) {}

            CurvePtr m_curve;
            StorageUnit m_x;
            StorageUnit m_y;
            StorageUnit m_z;
      };

      class PrecomputedMul2Table {
         public:
            virtual ~PrecomputedMul2Table() = default;
      };

      virtual ~PrimeOrderCurve() = default;

      /// Return the bit length of the group order
      virtual size_t order_bits() const = 0;

      /// Return the byte length of the scalar element
      virtual size_t scalar_bytes() const = 0;

      /// Return the byte length of a field element
      ///
      /// Each point consists of two field elements
      virtual size_t field_element_bytes() const = 0;

      /// Base point multiplication
      ///
      /// Multiply by the standard generator point g
      virtual ProjectivePoint mul_by_g(const Scalar& scalar, RandomNumberGenerator& rng) const = 0;

      /// Base point multiplication, returning only the x coordinate modulo the group order
      ///
      /// Multiply by the standard generator point g, then extract the x
      /// coordinate as an integer, then reduce the x coordinate modulo the
      /// group order
      virtual Scalar base_point_mul_x_mod_order(const Scalar& scalar, RandomNumberGenerator& rng) const = 0;

      /// Generic point multiplication
      ///
      /// Multiply an arbitrary point by a scalar
      virtual ProjectivePoint mul(const AffinePoint& pt, const Scalar& scalar, RandomNumberGenerator& rng) const = 0;

      /// Setup a table for 2-ary multiplication
      virtual std::unique_ptr<const PrecomputedMul2Table> mul2_setup(const AffinePoint& pt1,
                                                                     const AffinePoint& pt2) const = 0;

      /// Perform 2-ary multiplication (variable time)
      ///
      /// Compute s1*pt1 + s2*pt2 in variable time
      ///
      /// Returns nullopt if the produced point is the point at infinity
      virtual std::optional<ProjectivePoint> mul2_vartime(const PrecomputedMul2Table& table,
                                                          const Scalar& s1,
                                                          const Scalar& s2) const = 0;

      /// Perform 2-ary multiplication (variable time), reducing x modulo order
      ///
      /// Compute s1*pt1 + s2*pt2 in variable time, then extract the x coordinate
      /// of the result, and reduce x modulo the group order
      ///
      /// Returns nullopt if the produced point is the point at infinity
      virtual std::optional<Scalar> mul2_vartime_x_mod_order(const PrecomputedMul2Table& table,
                                                             const Scalar& s1,
                                                             const Scalar& s2) const = 0;

      /// Return the standard generator
      virtual AffinePoint generator() const = 0;

      /// Deserialize a point
      ///
      /// Both compressed and uncompressed encodings are accepted
      ///
      /// Note that the deprecated "hybrid" encoding is not supported here
      virtual std::optional<AffinePoint> deserialize_point(std::span<const uint8_t> bytes) const = 0;

      /// Deserialize a scalar
      ///
      /// This function requires the input length be exactly scalar_bytes long;
      /// it does not accept inputs that are shorter, or with excess leading
      /// zero padding bytes.
      virtual std::optional<Scalar> deserialize_scalar(std::span<const uint8_t> bytes) const = 0;

      /// Deserialize a scalar using ECDSA truncation rules
      ///
      /// ECDSA and other signature schemes use a specific rule for converting a hash
      /// output into a scalar.
      virtual Scalar scalar_from_bits_with_trunc(std::span<const uint8_t> bytes) const = 0;

      /// Reduce an integer modulo the group order
      ///
      /// The input can be at most twice the bit length of the order; if larger than this
      /// nullopt is returned
      virtual std::optional<Scalar> scalar_from_wide_bytes(std::span<const uint8_t> bytes) const = 0;

      virtual AffinePoint point_to_affine(const ProjectivePoint& pt) const = 0;

      virtual ProjectivePoint point_to_projective(const AffinePoint& pt) const = 0;

      virtual bool affine_point_is_identity(const AffinePoint& pt) const = 0;

      virtual ProjectivePoint point_double(const ProjectivePoint& pt) const = 0;

      virtual ProjectivePoint point_negate(const ProjectivePoint& pt) const = 0;

      virtual ProjectivePoint point_add(const ProjectivePoint& a, const ProjectivePoint& b) const = 0;

      virtual ProjectivePoint point_add_mixed(const ProjectivePoint& a, const AffinePoint& b) const = 0;

      virtual void serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const = 0;

      virtual void serialize_point_compressed(std::span<uint8_t> bytes, const AffinePoint& pt) const = 0;

      virtual void serialize_point_x(std::span<uint8_t> bytes, const AffinePoint& pt) const = 0;

      virtual void serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const = 0;

      /**
      * Return the scalar zero
      */
      virtual Scalar scalar_zero() const = 0;

      /**
      * Return the scalar one
      */
      virtual Scalar scalar_one() const = 0;

      /**
      * Return a small scalar
      */
      virtual Scalar scalar_from_u32(uint32_t x) const = 0;

      virtual Scalar scalar_add(const Scalar& a, const Scalar& b) const = 0;
      virtual Scalar scalar_sub(const Scalar& a, const Scalar& b) const = 0;
      virtual Scalar scalar_mul(const Scalar& a, const Scalar& b) const = 0;
      virtual Scalar scalar_square(const Scalar& s) const = 0;
      virtual Scalar scalar_invert(const Scalar& s) const = 0;
      virtual Scalar scalar_negate(const Scalar& s) const = 0;
      virtual bool scalar_is_zero(const Scalar& s) const = 0;
      virtual bool scalar_equal(const Scalar& a, const Scalar& b) const = 0;

      /**
      * Return a new random scalar
      */
      virtual Scalar random_scalar(RandomNumberGenerator& rng) const = 0;

      /**
      * RFC 9380 hash to curve
      *
      * This is currently only supported for a few specific curves
      */
      virtual ProjectivePoint hash_to_curve(std::string_view hash,
                                            std::span<const uint8_t> input,
                                            std::span<const uint8_t> domain_sep,
                                            bool random_oracle) const = 0;
};

}  // namespace Botan::PCurve

#endif
