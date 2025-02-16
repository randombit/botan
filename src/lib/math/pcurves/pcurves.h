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
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace Botan {

class BigInt;
class RandomNumberGenerator;

}  // namespace Botan

namespace Botan::PCurve {

/**
* An elliptic curve without cofactor in Weierstrass form
*/
class PrimeOrderCurve {
   public:
      /// Somewhat arbitrary maximum size for a field or scalar
      ///
      /// Sized to fit at least P-521
      static constexpr size_t MaximumBitLength = 521;

      static constexpr size_t MaximumByteLength = (MaximumBitLength + 7) / 8;

      /// Number of words used to store MaximumByteLength
      static constexpr size_t StorageWords = (MaximumByteLength + sizeof(word) - 1) / sizeof(word);

      /// @returns nullptr if the curve specified is not available
      static std::shared_ptr<const PrimeOrderCurve> from_name(std::string_view name) {
         if(auto id = PrimeOrderCurveId::from_string(name)) {
            return PrimeOrderCurve::from_id(id.value());
         } else {
            return {};
         }
      }

      /// @returns nullptr if the curve specified is not available
      static std::shared_ptr<const PrimeOrderCurve> from_id(PrimeOrderCurveId id);

      /// @returns nullptr if the parameters seem unsuitable for pcurves
      /// for example if the prime is too large
      ///
      /// This function *should* accept the same subset of curves as
      /// the EC_Group constructor that accepts BigInts.
      static std::shared_ptr<const PrimeOrderCurve> from_params(const BigInt& p,
                                                                const BigInt& a,
                                                                const BigInt& b,
                                                                const BigInt& base_x,
                                                                const BigInt& base_y,
                                                                const BigInt& order);

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

      /// Generic x-only point multiplication
      ///
      /// Multiply an arbitrary point by a scalar, returning only the x coordinate
      virtual secure_vector<uint8_t> mul_x_only(const AffinePoint& pt,
                                                const Scalar& scalar,
                                                RandomNumberGenerator& rng) const = 0;

      /// Setup a table for 2-ary multiplication
      virtual std::unique_ptr<const PrecomputedMul2Table> mul2_setup(const AffinePoint& p,
                                                                     const AffinePoint& pq) const = 0;

      /// Setup a table for 2-ary multiplication where the first point is the generator
      virtual std::unique_ptr<const PrecomputedMul2Table> mul2_setup_g(const AffinePoint& q) const = 0;

      /// Perform 2-ary multiplication (variable time)
      ///
      /// Compute p*x + q*y in variable time
      ///
      /// Returns nullopt if the produced point is the point at infinity
      virtual std::optional<ProjectivePoint> mul2_vartime(const PrecomputedMul2Table& table,
                                                          const Scalar& x,
                                                          const Scalar& y) const = 0;

      /// Perform 2-ary multiplication (constant time)
      ///
      /// Compute p*x + q*y
      ///
      /// Returns nullopt if the produced point is the point at infinity
      virtual std::optional<ProjectivePoint> mul_px_qy(const AffinePoint& p,
                                                       const Scalar& x,
                                                       const AffinePoint& q,
                                                       const Scalar& y,
                                                       RandomNumberGenerator& rng) const = 0;

      /// Perform 2-ary multiplication (variable time), reducing x modulo order
      ///
      /// Compute p*x + q*y in variable time, then extract the x coordinate of
      /// the result, and reduce x modulo the group order. Compare that value
      /// with v. If equal, returns true. Otherwise returns false, including if
      /// the produced point is the point at infinity
      virtual bool mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& table,
                                               const Scalar& v,
                                               const Scalar& x,
                                               const Scalar& y) const = 0;

      /// Return the standard generator
      virtual AffinePoint generator() const = 0;

      /// Deserialize a point
      ///
      /// Both compressed and uncompressed encodings are accepted
      ///
      /// Note that the deprecated "hybrid" encoding is not supported here
      virtual std::optional<AffinePoint> deserialize_point(std::span<const uint8_t> bytes) const = 0;

      /// Deserialize a scalar in [1,p)
      ///
      /// This function requires the input length be exactly scalar_bytes long;
      /// it does not accept inputs that are shorter, or with excess leading
      /// zero padding bytes.
      ///
      /// This function also rejects zero as an input, since in normal usage
      /// scalars are integers in Z_p*
      virtual std::optional<Scalar> deserialize_scalar(std::span<const uint8_t> bytes) const = 0;

      /// Reduce an integer modulo the group order
      ///
      /// The input can be at most twice the bit length of the order; if larger than this
      /// nullopt is returned
      virtual std::optional<Scalar> scalar_from_wide_bytes(std::span<const uint8_t> bytes) const = 0;

      virtual AffinePoint point_to_affine(const ProjectivePoint& pt) const = 0;

      virtual ProjectivePoint point_to_projective(const AffinePoint& pt) const = 0;

      virtual bool affine_point_is_identity(const AffinePoint& pt) const = 0;

      virtual AffinePoint point_negate(const AffinePoint& pt) const = 0;

      virtual ProjectivePoint point_add(const AffinePoint& a, const AffinePoint& b) const = 0;

      virtual void serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const = 0;

      virtual void serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const = 0;

      /**
      * Return the scalar one
      */
      virtual Scalar scalar_one() const = 0;

      /// Scalar addition
      virtual Scalar scalar_add(const Scalar& a, const Scalar& b) const = 0;

      /// Scalar subtraction
      virtual Scalar scalar_sub(const Scalar& a, const Scalar& b) const = 0;

      /// Scalar multiplication
      virtual Scalar scalar_mul(const Scalar& a, const Scalar& b) const = 0;

      /// Scalar squaring
      virtual Scalar scalar_square(const Scalar& s) const = 0;

      /// Scalar inversion
      virtual Scalar scalar_invert(const Scalar& s) const = 0;

      /// Scalar inversion (variable time)
      virtual Scalar scalar_invert_vartime(const Scalar& s) const = 0;

      /// Scalar negation
      virtual Scalar scalar_negate(const Scalar& s) const = 0;

      /// Test if scalar is zero
      virtual bool scalar_is_zero(const Scalar& s) const = 0;

      /// Test if two scalars are equal
      virtual bool scalar_equal(const Scalar& a, const Scalar& b) const = 0;

      /**
      * Return a new random scalar
      */
      virtual Scalar random_scalar(RandomNumberGenerator& rng) const = 0;

      /**
      * RFC 9380 hash to curve (NU variant)
      *
      * This is currently only supported for a few specific curves
      *
      * @param expand_message is a callback which must fill the provided output
      * span with a sequence of uniform bytes, or if this is not possible due to
      * length limitations or some other issue, throw an exception. It is
      * invoked to produce the `uniform_bytes` value; see RFC 9380 section 5.2
      */
      virtual AffinePoint hash_to_curve_nu(std::function<void(std::span<uint8_t>)> expand_message) const = 0;

      /**
      * RFC 9380 hash to curve (RO variant)
      *
      * This is currently only supported for a few specific curves
      *
      * @param expand_message is a callback which must fill the provided output
      * span with a sequence of uniform bytes, or if this is not possible due to
      * length limitations or some other issue, throw an exception. It is
      * invoked to produce the `uniform_bytes` value; see RFC 9380 section 5.2
      */
      virtual ProjectivePoint hash_to_curve_ro(std::function<void(std::span<uint8_t>)> expand_message) const = 0;
};

}  // namespace Botan::PCurve

#endif
