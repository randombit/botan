/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_scalar.h>

#include <botan/ec_group.h>
#include <botan/internal/ec_inner_data.h>

namespace Botan {

EC_Scalar EC_Scalar::_from_inner(std::unique_ptr<EC_Scalar_Data> inner) {
   return EC_Scalar(std::move(inner));
}

EC_Scalar::EC_Scalar(std::unique_ptr<EC_Scalar_Data> scalar) : m_scalar(std::move(scalar)) {
   BOTAN_ASSERT_NONNULL(m_scalar);
}

EC_Scalar::EC_Scalar(const EC_Scalar& other) : m_scalar(other.inner().clone()) {}

EC_Scalar::EC_Scalar(EC_Scalar&& other) noexcept : m_scalar(std::move(other.m_scalar)) {}

EC_Scalar& EC_Scalar::operator=(const EC_Scalar& other) {
   if(this != &other) {
      this->assign(other);
   }
   return (*this);
}

EC_Scalar& EC_Scalar::operator=(EC_Scalar&& other) noexcept {
   BOTAN_ARG_CHECK(_inner().group() == other._inner().group(), "Curve mismatch");
   std::swap(m_scalar, other.m_scalar);
   return (*this);
}

EC_Scalar::~EC_Scalar() = default;

size_t EC_Scalar::bytes() const {
   return m_scalar->bytes();
}

EC_Scalar EC_Scalar::from_bytes_with_trunc(const EC_Group& group, std::span<const uint8_t> bytes) {
   return EC_Scalar(group._data()->scalar_from_bytes_with_trunc(bytes));
}

EC_Scalar EC_Scalar::from_bytes_mod_order(const EC_Group& group, std::span<const uint8_t> bytes) {
   if(auto s = group._data()->scalar_from_bytes_mod_order(bytes)) {
      return EC_Scalar(std::move(s));
   } else {
      throw Decoding_Error("EC_Scalar::from_bytes_mod_order input invalid");
   }
}

EC_Scalar EC_Scalar::random(const EC_Group& group, RandomNumberGenerator& rng) {
   return EC_Scalar(group._data()->scalar_random(rng));
}

EC_Scalar EC_Scalar::one(const EC_Group& group) {
   return EC_Scalar(group._data()->scalar_one());
}

EC_Scalar EC_Scalar::from_bigint(const EC_Group& group, const BigInt& bn) {
   if(auto data = group._data()->scalar_from_bigint(bn)) {
      return EC_Scalar(std::move(data));
   } else {
      throw Invalid_Argument("EC_Scalar::from_bigint input out of range");
   }
}

BigInt EC_Scalar::to_bigint() const {
   secure_vector<uint8_t> bytes(m_scalar->bytes());
   m_scalar->serialize_to(bytes);
   return BigInt::from_bytes(bytes);
}

EC_Scalar EC_Scalar::gk_x_mod_order(const EC_Scalar& scalar, RandomNumberGenerator& rng, std::vector<BigInt>& ws) {
   const auto& group = scalar._inner().group();
   return EC_Scalar(group->gk_x_mod_order(scalar.inner(), rng, ws));
}

void EC_Scalar::serialize_to(std::span<uint8_t> bytes) const {
   inner().serialize_to(bytes);
}

void EC_Scalar::serialize_pair_to(std::span<uint8_t> bytes, const EC_Scalar& r, const EC_Scalar& s) {
   BOTAN_ARG_CHECK(r._inner().group() == s._inner().group(), "Curve mismatch");
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
      return EC_Scalar(std::move(v));
   } else {
      return {};
   }
}

EC_Scalar::EC_Scalar(const EC_Group& group, std::span<const uint8_t> bytes) {
   m_scalar = group._data()->scalar_deserialize(bytes);
   if(!m_scalar) {
      throw Decoding_Error("EC_Scalar::from_bytes is not a valid scalar value");
   }
}

bool EC_Scalar::is_zero() const {
   return inner().is_zero();
}

EC_Scalar EC_Scalar::invert() const {
   return EC_Scalar(inner().invert());
}

EC_Scalar EC_Scalar::invert_vartime() const {
   return EC_Scalar(inner().invert_vartime());
}

EC_Scalar EC_Scalar::negate() const {
   return EC_Scalar(inner().negate());
}

void EC_Scalar::square_self() {
   m_scalar->square_self();
}

EC_Scalar EC_Scalar::add(const EC_Scalar& x) const {
   return EC_Scalar(inner().add(x.inner()));
}

EC_Scalar EC_Scalar::sub(const EC_Scalar& x) const {
   return EC_Scalar(inner().sub(x.inner()));
}

EC_Scalar EC_Scalar::mul(const EC_Scalar& x) const {
   return EC_Scalar(inner().mul(x.inner()));
}

void EC_Scalar::assign(const EC_Scalar& x) {
   m_scalar->assign(x.inner());
}

bool EC_Scalar::is_eq(const EC_Scalar& x) const {
   return inner().is_eq(x.inner());
}

}  // namespace Botan
