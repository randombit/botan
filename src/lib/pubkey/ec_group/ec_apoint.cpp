/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_apoint.h>

#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/internal/ec_inner_data.h>

namespace Botan {

EC_AffinePoint::EC_AffinePoint(std::unique_ptr<EC_AffinePoint_Data> point) : m_point(std::move(point)) {
   BOTAN_ASSERT_NONNULL(m_point);
}

EC_AffinePoint::EC_AffinePoint(const EC_AffinePoint& other) : m_point(other.inner().clone()) {}

EC_AffinePoint::EC_AffinePoint(EC_AffinePoint&& other) noexcept : m_point(std::move(other.m_point)) {}

EC_AffinePoint& EC_AffinePoint::operator=(const EC_AffinePoint& other) {
   if(this != &other) {
      m_point = other.inner().clone();
   }
   return (*this);
}

EC_AffinePoint& EC_AffinePoint::operator=(EC_AffinePoint&& other) noexcept {
   m_point.swap(other.m_point);
   return (*this);
}

EC_AffinePoint::EC_AffinePoint(const EC_Group& group, std::span<const uint8_t> bytes) {
   m_point = group._data()->point_deserialize(bytes);
   if(!m_point) {
      throw Decoding_Error("Failed to deserialize elliptic curve point");
   }
}

EC_AffinePoint::EC_AffinePoint(const EC_Group& group, const EC_Point& pt) :
      EC_AffinePoint(group, pt.encode(EC_Point_Format::Uncompressed)) {}

size_t EC_AffinePoint::field_element_bytes() const {
   return inner().field_element_bytes();
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_ro(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::span<const uint8_t> domain_sep) {
   auto pt = group._data()->point_hash_to_curve_ro(hash_fn, input, domain_sep);
   return EC_AffinePoint(std::move(pt));
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_nu(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::span<const uint8_t> domain_sep) {
   auto pt = group._data()->point_hash_to_curve_nu(hash_fn, input, domain_sep);
   return EC_AffinePoint(std::move(pt));
}

EC_AffinePoint::~EC_AffinePoint() = default;

std::optional<EC_AffinePoint> EC_AffinePoint::deserialize(const EC_Group& group, std::span<const uint8_t> bytes) {
   auto pt = group._data()->point_deserialize(bytes);
   return EC_AffinePoint(std::move(pt));
}

EC_AffinePoint EC_AffinePoint::g_mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) {
   auto pt = scalar._inner().group()->point_g_mul(scalar.inner(), rng, ws);
   return EC_AffinePoint(std::move(pt));
}

EC_AffinePoint EC_AffinePoint::mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const {
   return EC_AffinePoint(inner().mul(scalar._inner(), rng, ws));
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
   return m_point->to_legacy_point();
}

EC_AffinePoint EC_AffinePoint::_from_inner(std::unique_ptr<EC_AffinePoint_Data> inner) {
   return EC_AffinePoint(std::move(inner));
}

const std::shared_ptr<const EC_Group_Data>& EC_AffinePoint::_group() const {
   return inner().group();
}

}  // namespace Botan
