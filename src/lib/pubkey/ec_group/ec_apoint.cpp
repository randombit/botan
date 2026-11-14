/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_apoint.h>

#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/mem_ops.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/ec_inner_data.h>
#include <botan/internal/mem_utils.h>

namespace Botan {

namespace {

EC_AffinePoint make_point(const std::shared_ptr<const EC_Group_Data>& group, PCurve::PrimeOrderCurve::AffinePoint pt) {
   return EC_AffinePoint::_from_inner(std::make_unique<EC_AffinePoint_Data>(group, std::move(pt)));
}

}  // namespace

EC_AffinePoint::EC_AffinePoint(std::unique_ptr<EC_AffinePoint_Data> point) : m_point(std::move(point)) {
   BOTAN_ASSERT_NONNULL(m_point);
}

EC_AffinePoint::EC_AffinePoint(const EC_AffinePoint& other) :
      m_point(std::make_unique<EC_AffinePoint_Data>(other.inner())) {}

EC_AffinePoint::EC_AffinePoint(EC_AffinePoint&& other) noexcept : m_point(std::move(other.m_point)) {}

EC_AffinePoint& EC_AffinePoint::operator=(const EC_AffinePoint& other) {
   if(this != &other) {
      if(m_point == nullptr) {
         m_point = std::make_unique<EC_AffinePoint_Data>(other.inner());
      } else {
         *m_point = other.inner();
      }
   }
   return (*this);
}

EC_AffinePoint& EC_AffinePoint::operator=(EC_AffinePoint&& other) noexcept {
   m_point.swap(other.m_point);
   return (*this);
}

EC_AffinePoint::EC_AffinePoint(const EC_Group& group, std::span<const uint8_t> bytes) {
   if(auto pt = EC_AffinePoint::deserialize(group, bytes)) {
      m_point = std::move(pt->m_point);
   } else {
      throw Decoding_Error("Failed to deserialize elliptic curve point");
   }
}

bool EC_AffinePoint::operator==(const EC_AffinePoint& other) const {
   if(this == &other) {
      return true;
   }

   // We are relying on EC_Group to ensure there is just a single shared_ptr
   // for any set of group params
   if(this->_group() != other._group()) {
      return false;
   }

   const auto a_is_id = this->is_identity();
   const auto b_is_id = other.is_identity();

   if(a_is_id || b_is_id) {
      return (a_is_id == b_is_id);
   }

   const auto a_xy = this->inner().uncompressed();
   const auto b_xy = other.inner().uncompressed();
   BOTAN_ASSERT_NOMSG(a_xy.size() == b_xy.size());

   return CT::is_equal(a_xy.data(), b_xy.data(), a_xy.size()).as_bool();
}

EC_AffinePoint EC_AffinePoint::identity(const EC_Group& group) {
   const auto& data = group._data();
   return make_point(data, data->pcurve().point_identity());
}

EC_AffinePoint EC_AffinePoint::generator(const EC_Group& group) {
   const auto& data = group._data();
   return make_point(data, data->pcurve().generator());
}

std::optional<EC_AffinePoint> EC_AffinePoint::from_bigint_xy(const EC_Group& group, const BigInt& x, const BigInt& y) {
   if(x.signum() < 0 || x >= group.get_p()) {
      return {};
   }
   if(y.signum() < 0 || y >= group.get_p()) {
      return {};
   }

   const size_t fe_bytes = group.get_p_bytes();
   std::vector<uint8_t> sec1(1 + 2 * fe_bytes);
   sec1[0] = 0x04;
   x.serialize_to(std::span{sec1}.subspan(1, fe_bytes));
   y.serialize_to(std::span{sec1}.last(fe_bytes));

   return EC_AffinePoint::deserialize_uncompressed(group, sec1);
}

std::pair<BigInt, BigInt> EC_AffinePoint::to_bigint_xy() const {
   std::vector<uint8_t> x_bytes(this->field_element_bytes());
   std::vector<uint8_t> y_bytes(this->field_element_bytes());
   this->serialize_x_to(x_bytes);
   this->serialize_y_to(y_bytes);
   return std::make_pair(BigInt::from_bytes(x_bytes), BigInt::from_bytes(y_bytes));
}

BigInt EC_AffinePoint::get_affine_x() const {
   return BigInt::from_bytes(this->x_bytes<std::vector<uint8_t>>());
}

BigInt EC_AffinePoint::get_affine_y() const {
   return BigInt::from_bytes(this->y_bytes<std::vector<uint8_t>>());
}

EC_Group EC_AffinePoint::group() const {
   return EC_Group(inner().group());
}

size_t EC_AffinePoint::field_element_bytes() const {
   return inner().group()->pcurve().field_element_bytes();
}

bool EC_AffinePoint::is_identity() const {
   return inner().is_identity();
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_ro(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::span<const uint8_t> domain_sep) {
   const auto& data = group._data();
   const auto& pcurve = data->pcurve();

   if(!pcurve.supports_hash_to_curve()) {
      throw Not_Implemented("Hash to curve is not implemented for this curve");
   }

   const auto pt = pcurve.hash_to_curve_ro(h2c_expand_message(hash_fn, data->order_bits(), input, domain_sep));
   return make_point(data, pcurve.point_to_affine(pt));
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_ro(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::string_view domain_sep) {
   return EC_AffinePoint::hash_to_curve_ro(group, hash_fn, input, as_span_of_bytes(domain_sep));
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_nu(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::span<const uint8_t> domain_sep) {
   const auto& data = group._data();
   const auto& pcurve = data->pcurve();

   if(!pcurve.supports_hash_to_curve()) {
      throw Not_Implemented("Hash to curve is not implemented for this curve");
   }

   auto pt = pcurve.hash_to_curve_nu(h2c_expand_message(hash_fn, data->order_bits(), input, domain_sep));
   return make_point(data, std::move(pt));
}

EC_AffinePoint EC_AffinePoint::hash_to_curve_nu(const EC_Group& group,
                                                std::string_view hash_fn,
                                                std::span<const uint8_t> input,
                                                std::string_view domain_sep) {
   return EC_AffinePoint::hash_to_curve_nu(group, hash_fn, input, as_span_of_bytes(domain_sep));
}

EC_AffinePoint::~EC_AffinePoint() = default;

std::optional<EC_AffinePoint> EC_AffinePoint::deserialize(const EC_Group& group, std::span<const uint8_t> bytes) {
   if(bytes.empty()) {
      return {};
   }

   switch(bytes[0]) {
      case 0x00:
         // The identity element (see SEC1 section 2.3.4)
         // TODO(Botan4) remove this - we should reject the identity encoding
         if(bytes.size() == 1) {
            return EC_AffinePoint::identity(group);
         } else {
            return {};
         }
      case 0x02:
      case 0x03:
         return EC_AffinePoint::deserialize_compressed(group, bytes);
      case 0x04:
         return EC_AffinePoint::deserialize_uncompressed(group, bytes);
      default:
         return {};
   }
}

std::optional<EC_AffinePoint> EC_AffinePoint::deserialize_compressed(const EC_Group& group,
                                                                     std::span<const uint8_t> bytes) {
   const auto& data = group._data();

   if(bytes.size() != 1 + data->p_bytes() || (bytes[0] != 0x02 && bytes[0] != 0x03)) {
      return {};
   }

   if(auto pt = data->pcurve().deserialize_point_compressed(bytes)) {
      return make_point(data, std::move(*pt));
   } else {
      return {};
   }
}

std::optional<EC_AffinePoint> EC_AffinePoint::deserialize_uncompressed(const EC_Group& group,
                                                                       std::span<const uint8_t> bytes) {
   const auto& data = group._data();

   if(bytes.size() != 1 + 2 * data->p_bytes() || bytes[0] != 0x04) {
      return {};
   }

   if(auto pt = data->pcurve().deserialize_point_uncompressed(bytes)) {
      return make_point(data, std::move(*pt));
   } else {
      return {};
   }
}

EC_AffinePoint EC_AffinePoint::g_mul(const EC_Scalar& scalar, RandomNumberGenerator& rng) {
   const auto& group = scalar._inner().group();
   const auto& pcurve = group->pcurve();
   return make_point(group, pcurve.point_to_affine(pcurve.mul_by_g(scalar._inner().value(), rng)));
}

EC_AffinePoint EC_AffinePoint::mul(const EC_Scalar& scalar, RandomNumberGenerator& rng) const {
   const auto& group = inner().group();
   BOTAN_ARG_CHECK(scalar._inner().group() == group, "Curve mismatch");
   const auto& pcurve = group->pcurve();
   return make_point(group, pcurve.point_to_affine(pcurve.mul(inner().value(), scalar._inner().value(), rng)));
}

secure_vector<uint8_t> EC_AffinePoint::mul_x_only(const EC_Scalar& scalar, RandomNumberGenerator& rng) const {
   const auto& group = inner().group();
   BOTAN_ARG_CHECK(scalar._inner().group() == group, "Curve mismatch");
   return group->pcurve().mul_x_only(inner().value(), scalar._inner().value(), rng);
}

std::optional<EC_AffinePoint> EC_AffinePoint::mul_px_qy(const EC_AffinePoint& p,
                                                        const EC_Scalar& x,
                                                        const EC_AffinePoint& q,
                                                        const EC_Scalar& y,
                                                        RandomNumberGenerator& rng) {
   const auto& group = p._group();
   const auto& pcurve = group->pcurve();

   if(auto pt = pcurve.mul_px_qy(p.inner().value(), x._inner().value(), q.inner().value(), y._inner().value(), rng)) {
      return make_point(group, pcurve.point_to_affine(*pt));
   } else {
      return {};
   }
}

EC_AffinePoint EC_AffinePoint::add(const EC_AffinePoint& q) const {
   const auto& group = inner().group();
   const auto& pcurve = group->pcurve();
   return make_point(group, pcurve.point_to_affine(pcurve.point_add(inner().value(), q.inner().value())));
}

EC_AffinePoint EC_AffinePoint::negate() const {
   const auto& group = inner().group();
   return make_point(group, group->pcurve().point_negate(inner().value()));
}

std::vector<uint8_t> EC_AffinePoint::serialize(EC_Point_Format format) const {
   if(format == EC_Point_Format::Compressed) {
      return this->serialize_compressed();
   } else if(format == EC_Point_Format::Uncompressed) {
      return this->serialize_uncompressed();
   } else {
      throw Invalid_Argument("Unknown EC point format");
   }
}

void EC_AffinePoint::serialize_x_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == fe_bytes, "Invalid output size");
   copy_mem(bytes, inner().uncompressed().subspan(1, fe_bytes));
}

void EC_AffinePoint::serialize_y_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == fe_bytes, "Invalid output size");
   copy_mem(bytes, inner().uncompressed().subspan(1 + fe_bytes, fe_bytes));
}

void EC_AffinePoint::serialize_xy_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == 2 * fe_bytes, "Invalid output size");
   copy_mem(bytes, inner().uncompressed().last(2 * fe_bytes));
}

void EC_AffinePoint::serialize_compressed_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == 1 + fe_bytes, "Invalid output size");
   const bool y_is_odd = (inner().uncompressed().back() & 0x01) == 0x01;

   BufferStuffer stuffer(bytes);
   stuffer.append(y_is_odd ? 0x03 : 0x02);
   this->serialize_x_to(stuffer.next(fe_bytes));
}

void EC_AffinePoint::serialize_uncompressed_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == 1 + 2 * fe_bytes, "Invalid output size");
   copy_mem(bytes, inner().uncompressed());
}

EC_AffinePoint EC_AffinePoint::_from_inner(std::unique_ptr<EC_AffinePoint_Data> inner) {
   return EC_AffinePoint(std::move(inner));
}

const std::shared_ptr<const EC_Group_Data>& EC_AffinePoint::_group() const {
   return inner().group();
}

void EC_AffinePoint::_const_time_poison() const {
   inner()._const_time_poison();
}

void EC_AffinePoint::_const_time_unpoison() const {
   inner()._const_time_unpoison();
}

}  // namespace Botan
