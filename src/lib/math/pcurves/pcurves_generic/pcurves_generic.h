/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_GENERIC_H_
#define BOTAN_PCURVES_GENERIC_H_

#include <botan/internal/pcurves.h>

namespace Botan::PCurve {

class GenericPrimeOrderCurve final : public PrimeOrderCurve {
   public:
      GenericPrimeOrderCurve(const BigInt& p,
                             const BigInt& a,
                             const BigInt& b,
                             const BigInt& base_x,
                             const BigInt& base_y,
                             const BigInt& order);

      size_t order_bits() const override;

      size_t scalar_bytes() const override;

      size_t field_element_bytes() const override;

      ProjectivePoint mul_by_g(const Scalar& scalar, RandomNumberGenerator& rng) const override;

      ProjectivePoint mul(const AffinePoint& pt, const Scalar& scalar, RandomNumberGenerator& rng) const override;

      std::unique_ptr<const PrecomputedMul2Table> mul2_setup(const AffinePoint& x, const AffinePoint& y) const override;

      std::optional<ProjectivePoint> mul2_vartime(const PrecomputedMul2Table& tableb,
                                                  const Scalar& s1,
                                                  const Scalar& s2) const override;

      std::optional<ProjectivePoint> mul_px_qy(const AffinePoint& p,
                                               const Scalar& x,
                                               const AffinePoint& q,
                                               const Scalar& y,
                                               RandomNumberGenerator& rng) const override;

      bool mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& tableb,
                                       const Scalar& v,
                                       const Scalar& s1,
                                       const Scalar& s2) const override;

      Scalar base_point_mul_x_mod_order(const Scalar& scalar, RandomNumberGenerator& rng) const override;

      AffinePoint generator() const override;

      AffinePoint point_to_affine(const ProjectivePoint& pt) const override;

      ProjectivePoint point_to_projective(const AffinePoint& pt) const override;

      ProjectivePoint point_double(const ProjectivePoint& pt) const override;

      ProjectivePoint point_add(const ProjectivePoint& a, const ProjectivePoint& b) const override;

      ProjectivePoint point_add_mixed(const ProjectivePoint& a, const AffinePoint& b) const override;

      AffinePoint point_negate(const AffinePoint& pt) const override;

      bool affine_point_is_identity(const AffinePoint& pt) const override;

      void serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const override;

      void serialize_point_compressed(std::span<uint8_t> bytes, const AffinePoint& pt) const override;

      void serialize_point_x(std::span<uint8_t> bytes, const AffinePoint& pt) const override;

      void serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const override;

      std::optional<Scalar> deserialize_scalar(std::span<const uint8_t> bytes) const override;

      std::optional<Scalar> scalar_from_wide_bytes(std::span<const uint8_t> bytes) const override;

      std::optional<AffinePoint> deserialize_point(std::span<const uint8_t> bytes) const override;

      AffinePoint hash_to_curve_nu(std::string_view hash,
                                   std::span<const uint8_t> input,
                                   std::span<const uint8_t> domain_sep) const override;

      ProjectivePoint hash_to_curve_ro(std::string_view hash,
                                       std::span<const uint8_t> input,
                                       std::span<const uint8_t> domain_sep) const override;

      Scalar scalar_add(const Scalar& a, const Scalar& b) const override;

      Scalar scalar_sub(const Scalar& a, const Scalar& b) const override;

      Scalar scalar_mul(const Scalar& a, const Scalar& b) const override;

      Scalar scalar_square(const Scalar& s) const override;

      Scalar scalar_invert(const Scalar& s) const override;

      Scalar scalar_negate(const Scalar& s) const override;

      bool scalar_is_zero(const Scalar& s) const override;

      bool scalar_equal(const Scalar& a, const Scalar& b) const override;

      Scalar scalar_zero() const override;

      Scalar scalar_one() const override;

      Scalar scalar_from_u32(uint32_t x) const override;

      Scalar random_scalar(RandomNumberGenerator& rng) const override;

   private:
      const size_t m_order_bits;
      const size_t m_order_bytes;
      const size_t m_fe_bytes;
      /// ???
};

}  // namespace Botan::PCurve

#endif
