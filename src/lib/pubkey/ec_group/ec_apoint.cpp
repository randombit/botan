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

#if defined(BOTAN_HAS_LEGACY_EC_POINT)

EC_Point EC_AffinePoint::to_legacy_point() const {
   return m_point->to_legacy_point();
}

EC_AffinePoint::EC_AffinePoint(const EC_Group& group, const EC_Point& pt) :
      EC_AffinePoint(group, pt.encode(EC_Point_Format::Uncompressed)) {}

#endif

bool EC_AffinePoint::operator==(const EC_AffinePoint& other) const {
   if(this == &other) {
      return true;
   }

   // We are relying on EC_Group to ensure there is just a single shared_ptr
   // for any set of group params
   if(this->_group() != other._group()) {
      return false;
   }

   auto a_is_id = this->is_identity();
   auto b_is_id = other.is_identity();

   if(a_is_id || b_is_id) {
      return (a_is_id == b_is_id);
   }

   auto a_xy = this->serialize_uncompressed();
   auto b_xy = other.serialize_uncompressed();
   BOTAN_ASSERT_NOMSG(a_xy.size() == b_xy.size());

   return CT::is_equal(a_xy.data(), b_xy.data(), a_xy.size()).as_bool();
}

EC_AffinePoint EC_AffinePoint::identity(const EC_Group& group) {
   const uint8_t id_encoding[1] = {0};
   return EC_AffinePoint(group, id_encoding);
}

EC_AffinePoint EC_AffinePoint::generator(const EC_Group& group) {
   // TODO it would be nice to improve this (pcurves supports returning generator directly)
   try {
      return EC_AffinePoint::from_bigint_xy(group, group.get_g_x(), group.get_g_y()).value();
   } catch(...) {
      throw Internal_Error("EC_AffinePoint::generator curve rejected generator");
   }
}

std::optional<EC_AffinePoint> EC_AffinePoint::from_bigint_xy(const EC_Group& group, const BigInt& x, const BigInt& y) {
   if(x.is_negative() || x >= group.get_p()) {
      return {};
   }
   if(y.is_negative() || y >= group.get_p()) {
      return {};
   }

   const size_t fe_bytes = group.get_p_bytes();
   std::vector<uint8_t> sec1(1 + 2 * fe_bytes);
   sec1[0] = 0x04;
   x.serialize_to(std::span{sec1}.subspan(1, fe_bytes));
   y.serialize_to(std::span{sec1}.last(fe_bytes));

   return EC_AffinePoint::deserialize(group, sec1);
}

size_t EC_AffinePoint::field_element_bytes() const {
   return inner().field_element_bytes();
}

bool EC_AffinePoint::is_identity() const {
   return inner().is_identity();
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
   if(auto pt = group._data()->point_deserialize(bytes)) {
      return EC_AffinePoint(std::move(pt));
   } else {
      return {};
   }
}

EC_AffinePoint EC_AffinePoint::g_mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) {
   auto pt = scalar._inner().group()->point_g_mul(scalar.inner(), rng, ws);
   return EC_AffinePoint(std::move(pt));
}

EC_AffinePoint EC_AffinePoint::mul(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const {
   return EC_AffinePoint(inner().mul(scalar._inner(), rng, ws));
}

secure_vector<uint8_t> EC_AffinePoint::mul_x_only(const EC_Scalar& scalar,
                                                  RandomNumberGenerator& rng,
                                                  std::vector<BigInt>& ws) const {
   return inner().mul_x_only(scalar._inner(), rng, ws);
}

std::optional<EC_AffinePoint> EC_AffinePoint::mul_px_qy(const EC_AffinePoint& p,
                                                        const EC_Scalar& x,
                                                        const EC_AffinePoint& q,
                                                        const EC_Scalar& y,
                                                        RandomNumberGenerator& rng) {
   auto pt = p._inner().group()->mul_px_qy(p._inner(), x._inner(), q._inner(), y._inner(), rng);
   if(pt) {
      return EC_AffinePoint(std::move(pt));
   } else {
      return {};
   }
}

EC_AffinePoint EC_AffinePoint::add(const EC_AffinePoint& q) const {
   auto pt = _inner().group()->affine_add(_inner(), q._inner());
   return EC_AffinePoint(std::move(pt));
}

EC_AffinePoint EC_AffinePoint::negate() const {
   auto pt = this->_inner().group()->affine_neg(this->_inner());
   return EC_AffinePoint(std::move(pt));
}

std::vector<uint8_t> EC_AffinePoint::serialize(EC_Point_Format format) const {
   if(format == EC_Point_Format::Compressed) {
      return this->serialize_compressed();
   } else if(format == EC_Point_Format::Uncompressed) {
      return this->serialize_uncompressed();
   } else {
      // The deprecated "hybrid" point encoding
      // TODO(Botan4) Remove this
      auto enc = this->serialize_uncompressed();
      const bool y_is_odd = (enc[enc.size() - 1] & 0x01) == 0x01;
      enc.front() = y_is_odd ? 0x07 : 0x06;
      return enc;
   }
}

void EC_AffinePoint::serialize_x_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   m_point->serialize_x_to(bytes);
}

void EC_AffinePoint::serialize_y_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   m_point->serialize_y_to(bytes);
}

void EC_AffinePoint::serialize_xy_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   m_point->serialize_xy_to(bytes);
}

void EC_AffinePoint::serialize_compressed_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   m_point->serialize_compressed_to(bytes);
}

void EC_AffinePoint::serialize_uncompressed_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   m_point->serialize_uncompressed_to(bytes);
}

EC_AffinePoint EC_AffinePoint::_from_inner(std::unique_ptr<EC_AffinePoint_Data> inner) {
   return EC_AffinePoint(std::move(inner));
}

const std::shared_ptr<const EC_Group_Data>& EC_AffinePoint::_group() const {
   return inner().group();
}

}  // namespace Botan
