/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_scalar.h>

#include <botan/ec_group.h>
#include <botan/internal/ec_inner_data.h>
#include <algorithm>

namespace Botan {

namespace {

EC_Scalar make_scalar(const std::shared_ptr<const EC_Group_Data>& group, PCurve::PrimeOrderCurve::Scalar v) {
   return EC_Scalar::_from_inner(std::make_unique<EC_Scalar_Data>(group, std::move(v)));
}

}  // namespace

EC_Scalar EC_Scalar::_from_inner(std::unique_ptr<EC_Scalar_Data> inner) {
   return EC_Scalar(std::move(inner));
}

void EC_Scalar::_const_time_poison() const {
   m_scalar->value()._const_time_poison();
}

void EC_Scalar::_const_time_unpoison() const {
   m_scalar->value()._const_time_unpoison();
}

EC_Scalar::EC_Scalar(std::unique_ptr<EC_Scalar_Data> scalar) : m_scalar(std::move(scalar)) {
   BOTAN_ASSERT_NONNULL(m_scalar);
}

EC_Scalar::EC_Scalar(const EC_Scalar& other) : m_scalar(std::make_unique<EC_Scalar_Data>(other.inner())) {}

EC_Scalar::EC_Scalar(EC_Scalar&& other) noexcept : m_scalar(std::move(other.m_scalar)) {}

EC_Scalar& EC_Scalar::operator=(const EC_Scalar& other) {
   if(this != &other) {
      if(m_scalar == nullptr) {
         m_scalar = std::make_unique<EC_Scalar_Data>(other.inner());
      } else {
         *m_scalar = other.inner();
      }
   }
   return (*this);
}

EC_Scalar& EC_Scalar::operator=(EC_Scalar&& other) noexcept {
   if(this != &other) {
      // Even a cross-curve swap is accepted here
      std::swap(m_scalar, other.m_scalar);
   }
   return (*this);
}

EC_Scalar::~EC_Scalar() = default;

EC_Group EC_Scalar::group() const {
   return EC_Group(inner().group());
}

size_t EC_Scalar::bytes() const {
   return inner().group()->order_bytes();
}

EC_Scalar EC_Scalar::from_bytes_with_trunc(const EC_Group& group, std::span<const uint8_t> bytes) {
   const size_t order_bits = group.get_order_bits();
   const size_t bit_length = 8 * bytes.size();

   if(bit_length < order_bits) {
      // No shifting required, but might still need to reduce by modulus
      return EC_Scalar::from_bytes_mod_order(group, bytes);
   } else {
      const size_t shift = bit_length - order_bits;

      const size_t new_length = bytes.size() - (shift / 8);
      const size_t bit_shift = shift % 8;

      if(bit_shift == 0) {
         // Easy case just read different bytes
         return EC_Scalar::from_bytes_mod_order(group, bytes.first(new_length));
      } else {
         std::vector<uint8_t> sbytes(new_length);

         uint8_t carry = 0;
         for(size_t i = 0; i != new_length; ++i) {
            const uint8_t w = bytes[i];
            sbytes[i] = (w >> bit_shift) | carry;
            carry = w << (8 - bit_shift);
         }

         return EC_Scalar::from_bytes_mod_order(group, sbytes);
      }
   }
}

EC_Scalar EC_Scalar::from_bytes_mod_order(const EC_Group& group, std::span<const uint8_t> bytes) {
   const auto& data = group._data();

   if(bytes.size() <= 2 * data->order_bytes()) {
      if(auto s = data->pcurve().scalar_from_wide_bytes(bytes)) {
         return make_scalar(data, std::move(*s));
      }
   }

   throw Decoding_Error("EC_Scalar::from_bytes_mod_order input invalid");
}

EC_Scalar EC_Scalar::random(const EC_Group& group, RandomNumberGenerator& rng) {
   const auto& data = group._data();
   return make_scalar(data, data->pcurve().random_scalar(rng));
}

EC_Scalar EC_Scalar::one(const EC_Group& group) {
   const auto& data = group._data();
   return make_scalar(data, data->pcurve().scalar_one());
}

EC_Scalar EC_Scalar::from_bigint(const EC_Group& group, const BigInt& bn) {
   if(bn > 0 && bn < group.get_order()) {
      if(auto s = EC_Scalar::deserialize(group, bn.serialize(group.get_order_bytes()))) {
         return std::move(*s);
      }
   }

   throw Invalid_Argument("EC_Scalar::from_bigint input out of range");
}

BigInt EC_Scalar::to_bigint() const {
   secure_vector<uint8_t> bytes(this->bytes());
   this->serialize_to(bytes);
   return BigInt::from_bytes(bytes);
}

//static
EC_Scalar EC_Scalar::gk_x_mod_order(const EC_Scalar& scalar, RandomNumberGenerator& rng) {
   const auto& group = scalar.inner().group();
   return make_scalar(group, group->pcurve().base_point_mul_x_mod_order(scalar.inner().value(), rng));
}

void EC_Scalar::serialize_to(std::span<uint8_t> bytes) const {
   const auto& group = inner().group();
   BOTAN_ARG_CHECK(bytes.size() == group->order_bytes(), "Invalid output length");
   group->pcurve().serialize_scalar(bytes, inner().value());
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
   const auto& data = group._data();

   if(bytes.size() != data->order_bytes()) {
      return {};
   }

   if(auto s = data->pcurve().deserialize_scalar(bytes)) {
      return make_scalar(data, std::move(*s));
   } else {
      return {};
   }
}

EC_Scalar::EC_Scalar(const EC_Group& group, std::span<const uint8_t> bytes) {
   if(auto s = EC_Scalar::deserialize(group, bytes)) {
      m_scalar = std::move(s->m_scalar);
   } else {
      throw Decoding_Error("EC_Scalar::from_bytes is not a valid scalar value");
   }
}

bool EC_Scalar::is_zero() const {
   return inner().group()->pcurve().scalar_is_zero(inner().value());
}

EC_Scalar EC_Scalar::invert() const {
   const auto& group = inner().group();
   return make_scalar(group, group->pcurve().scalar_invert(inner().value()));
}

EC_Scalar EC_Scalar::invert_vartime() const {
   const auto& group = inner().group();
   return make_scalar(group, group->pcurve().scalar_invert_vartime(inner().value()));
}

EC_Scalar EC_Scalar::negate() const {
   const auto& group = inner().group();
   return make_scalar(group, group->pcurve().scalar_negate(inner().value()));
}

void EC_Scalar::square_self() {
   // TODO square in place
   m_scalar->set_value(inner().group()->pcurve().scalar_square(inner().value()));
}

EC_Scalar EC_Scalar::add(const EC_Scalar& x) const {
   const auto& group = inner().group();
   BOTAN_ARG_CHECK(group == x.inner().group(), "Curve mismatch");
   return make_scalar(group, group->pcurve().scalar_add(inner().value(), x.inner().value()));
}

EC_Scalar EC_Scalar::sub(const EC_Scalar& x) const {
   const auto& group = inner().group();
   BOTAN_ARG_CHECK(group == x.inner().group(), "Curve mismatch");
   return make_scalar(group, group->pcurve().scalar_sub(inner().value(), x.inner().value()));
}

EC_Scalar EC_Scalar::mul(const EC_Scalar& x) const {
   const auto& group = inner().group();
   BOTAN_ARG_CHECK(group == x.inner().group(), "Curve mismatch");
   return make_scalar(group, group->pcurve().scalar_mul(inner().value(), x.inner().value()));
}

void EC_Scalar::assign(const EC_Scalar& x) {
   (*this) = x;
}

void EC_Scalar::zeroize() {
   m_scalar->zeroize();
}

bool EC_Scalar::is_eq(const EC_Scalar& x) const {
   const auto& group = inner().group();

   if(group != x.inner().group()) {
      return false;
   }

   return group->pcurve().scalar_equal(inner().value(), x.inner().value());
}

//static
EC_Scalar EC_Scalar::hash(const EC_Group& group,
                          std::string_view hash_fn,
                          std::span<const uint8_t> input,
                          std::span<const uint8_t> domain_sep) {
   /*
   RFC 9380 Section 5.2
      L = ceil((ceil(log2(p)) + k) / 8), where k is the security
      parameter of the suite (e.g., k = 128)
   */
   const size_t scalar_bits = group.get_order_bits();
   const size_t security_level = std::min<size_t>((scalar_bits + 1) / 2, 256);
   secure_vector<uint8_t> uniform_bytes((scalar_bits + security_level + 7) / 8);

   h2c_expand_message(hash_fn, scalar_bits, input, domain_sep)(uniform_bytes);

   return EC_Scalar::from_bytes_mod_order(group, uniform_bytes);
}

}  // namespace Botan
