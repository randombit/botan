/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_scalar.h>

#include <botan/ec_group.h>
#include <botan/internal/ec_inner_data.h>

namespace Botan {

EC_Scalar::EC_Scalar(std::shared_ptr<EC_Group_Data> group, std::unique_ptr<EC_Scalar_Data> scalar) :
      m_group(std::move(group)), m_scalar(std::move(scalar)), m_scalar_bytes(m_group->order_bytes()) {}

EC_Scalar::EC_Scalar(const EC_Group& group, std::unique_ptr<EC_Scalar_Data> scalar) :
      m_group(group._data()), m_scalar(std::move(scalar)), m_scalar_bytes(m_group->order_bytes()) {}

EC_Scalar::EC_Scalar(const EC_Scalar& other) :
      m_group(other.m_group), m_scalar(other.inner().clone()), m_scalar_bytes(m_group->order_bytes()) {}

EC_Scalar::EC_Scalar(EC_Scalar&& other) noexcept :
      m_group(std::move(other.m_group)), m_scalar(std::move(other.m_scalar)), m_scalar_bytes(m_group->order_bytes()) {}

EC_Scalar::~EC_Scalar() = default;

EC_Scalar EC_Scalar::from_bytes_with_trunc(const EC_Group& group, std::span<const uint8_t> bytes) {
   return EC_Scalar(group, group._data()->scalar_from_bytes_with_trunc(bytes));
}

EC_Scalar EC_Scalar::from_bytes_mod_order(const EC_Group& group, std::span<const uint8_t> bytes) {
   return EC_Scalar(group, group._data()->scalar_from_bytes_mod_order(bytes));
}

EC_Scalar EC_Scalar::random(const EC_Group& group, RandomNumberGenerator& rng) {
   return EC_Scalar(group, group._data()->scalar_random(rng));
}

EC_Scalar EC_Scalar::one(const EC_Group& group) {
   return EC_Scalar(group, group._data()->scalar_one());
}

EC_Scalar EC_Scalar::from_bigint(const EC_Group& group, const BigInt& bn) {
   BOTAN_ARG_CHECK(bn.is_positive() && bn <= group._data()->order(), "EC_Scalar::from_bigint out of range");
   return EC_Scalar(group, group._data()->scalar_from_bigint(bn));
}

EC_Scalar EC_Scalar::gk_x_mod_order(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) {
   const auto& group = scalar.group();
   return EC_Scalar(group, group->gk_x_mod_order(scalar.inner(), rng, ws));
}

void EC_Scalar::serialize_to(std::span<uint8_t> bytes) const {
   group()->scalar_serialize_to(inner(), bytes);
}

void EC_Scalar::serialize_pair_to(std::span<uint8_t> bytes, const EC_Scalar& r, const EC_Scalar& s) {
   BOTAN_ARG_CHECK(r.group() == s.group(), "Curve mismatch");
   const size_t scalar_bytes = r.bytes();
   BOTAN_ARG_CHECK(bytes.size() == 2 * scalar_bytes, "Invalid output length");
   r.serialize_to(bytes.first(scalar_bytes));
   s.serialize_to(bytes.last(scalar_bytes));
}

std::optional<std::pair<EC_Scalar, EC_Scalar>> EC_Scalar::deserialize_pair(const EC_Group& group,
                                                                           std::span<const uint8_t> bytes) {
   if(bytes.size() % 2 != 0) {
      return {};
   }

   const size_t half = bytes.size() / 2;

   auto r = EC_Scalar::deserialize(group, bytes.first(half));
   auto s = EC_Scalar::deserialize(group, bytes.last(half));

   if(r && s) {
      return std::make_pair(r.value(), s.value());
   } else {
      return {};
   }
}

std::optional<EC_Scalar> EC_Scalar::deserialize(const EC_Group& group, std::span<const uint8_t> bytes) {
   if(auto v = group._data()->scalar_deserialize(bytes)) {
      return EC_Scalar(group, std::move(v));
   } else {
      return {};
   }
}

bool EC_Scalar::is_zero() const {
   return group()->scalar_is_zero(inner());
}

EC_Scalar EC_Scalar::invert() const {
   return EC_Scalar(group(), group()->scalar_invert(inner()));
}

EC_Scalar EC_Scalar::negate() const {
   return EC_Scalar(m_group, group()->scalar_negate(inner()));
}

void EC_Scalar::square_self() {
   group()->scalar_square_self(*m_scalar);
}

EC_Scalar EC_Scalar::add(const EC_Scalar& x) const {
   BOTAN_ARG_CHECK(group() == x.group(), "Curve mismatch");
   return EC_Scalar(group(), group()->scalar_add(inner(), x.inner()));
}

EC_Scalar EC_Scalar::sub(const EC_Scalar& x) const {
   BOTAN_ARG_CHECK(group() == x.group(), "Curve mismatch");
   return EC_Scalar(group(), group()->scalar_sub(inner(), x.inner()));
}

EC_Scalar EC_Scalar::mul(const EC_Scalar& x) const {
   BOTAN_ARG_CHECK(group() == x.group(), "Curve mismatch");
   return EC_Scalar(group(), group()->scalar_mul(inner(), x.inner()));
}

void EC_Scalar::assign(const EC_Scalar& x) {
   BOTAN_ARG_CHECK(group() == x.group(), "Curve mismatch");
   group()->scalar_assign(*m_scalar, x.inner());
}

bool EC_Scalar::is_eq(const EC_Scalar& x) const {
   BOTAN_ARG_CHECK(group() == x.group(), "Curve mismatch");
   return group()->scalar_is_eq(inner(), x.inner());
}

}  // namespace Botan
