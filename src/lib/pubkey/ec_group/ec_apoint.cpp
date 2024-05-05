/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_apoint.h>

#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/internal/ec_inner_data.h>

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   #include <botan/internal/ec_h2c.h>
#endif

namespace Botan {

EC_AffinePoint::EC_AffinePoint(std::shared_ptr<EC_Group_Data> group, std::unique_ptr<EC_Point_Data> point) :
      m_group(std::move(group)), m_point(std::move(point)), m_fe_bytes(m_point->field_element_bytes()) {}

EC_AffinePoint::EC_AffinePoint(const EC_AffinePoint& other) :
      m_group(other.m_group),
      m_point(std::make_unique<EC_Point_Data>(other.m_point->value())),
      m_fe_bytes(m_point->field_element_bytes()) {}

EC_AffinePoint::EC_AffinePoint(EC_AffinePoint&& other) noexcept :
      m_group(std::move(other.m_group)),
      m_point(std::move(other.m_point)),
      m_fe_bytes(m_point->field_element_bytes()) {}

EC_AffinePoint::EC_AffinePoint(const EC_Group& group, const EC_Point& pt) :
      m_group(group._data()),
      m_point(std::make_unique<EC_Point_Data>(pt)),
      m_fe_bytes(m_point->field_element_bytes()) {}

EC_AffinePoint::EC_AffinePoint(std::shared_ptr<EC_Group_Data> group, EC_Point&& pt) :
      m_group(std::move(group)),
      m_point(std::make_unique<EC_Point_Data>(std::move(pt))),
      m_fe_bytes(m_point->field_element_bytes()) {}

EC_AffinePoint EC_AffinePoint::hash_to_curve_ro(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::span<const uint8_t> domain_sep) {
#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   auto pt = hash_to_curve_sswu(group, hash_fn, input, domain_sep, true);
   auto v = std::make_unique<EC_Point_Data>(std::move(pt));
   return EC_AffinePoint(group._data(), std::move(v));
#else
   BOTAN_UNUSED(group, hash_fn, input, domain_sep);
   throw Not_Implemented("Hashing to curve not available in this build");
#endif
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_nu(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::span<const uint8_t> domain_sep) {
#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   auto pt = hash_to_curve_sswu(group, hash_fn, input, domain_sep, false);
   auto v = std::make_unique<EC_Point_Data>(std::move(pt));
   return EC_AffinePoint(group._data(), std::move(v));
#else
   BOTAN_UNUSED(group, hash_fn, input, domain_sep);
   throw Not_Implemented("Hashing to curve not available in this build");
#endif
}

EC_AffinePoint::~EC_AffinePoint() = default;

std::optional<EC_AffinePoint> EC_AffinePoint::deserialize(const EC_Group& group, std::span<const uint8_t> bytes) {
   try {
      auto pt = group.OS2ECP(bytes);
      auto v = std::make_unique<EC_Point_Data>(std::move(pt));
      return EC_AffinePoint(group._data(), std::move(v));
   } catch(...) {
      return std::nullopt;
   }
}

EC_AffinePoint EC_AffinePoint::g_mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) {
   auto pt = scalar.m_group->blinded_base_point_multiply(scalar.m_scalar->value(), rng, ws);
   auto v = std::make_unique<EC_Point_Data>(std::move(pt));
   return EC_AffinePoint(scalar.m_group, std::move(v));
}

EC_AffinePoint EC_AffinePoint::mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const {
   BOTAN_ARG_CHECK(scalar.m_group == m_group, "Curve mismatch");

   EC_Point_Var_Point_Precompute mul(m_point->value(), rng, ws);

   const auto order = m_group->order() * m_group->cofactor();
   auto pt = mul.mul(scalar.m_scalar->value(), rng, order, ws);
   auto v = std::make_unique<EC_Point_Data>(std::move(pt));
   return EC_AffinePoint(m_group, std::move(v));
}

void EC_AffinePoint::serialize_x_to(std::span<uint8_t> bytes) const {
   m_point->serialize_x_to(bytes);
}

void EC_AffinePoint::serialize_y_to(std::span<uint8_t> bytes) const {
   m_point->serialize_y_to(bytes);
}

void EC_AffinePoint::serialize_xy_to(std::span<uint8_t> bytes) const {
   m_point->serialize_xy_to(bytes);
}

void EC_AffinePoint::serialize_compressed_to(std::span<uint8_t> bytes) const {
   m_point->serialize_compressed_to(bytes);
}

void EC_AffinePoint::serialize_uncompressed_to(std::span<uint8_t> bytes) const {
   m_point->serialize_uncompressed_to(bytes);
}

EC_Point EC_AffinePoint::to_legacy_point() const {
   return m_point->value();
}

}  // namespace Botan
