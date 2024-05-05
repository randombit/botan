/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_inner_data.h>

namespace Botan {

EC_Group_Data::EC_Group_Data(const BigInt& p,
                             const BigInt& a,
                             const BigInt& b,
                             const BigInt& g_x,
                             const BigInt& g_y,
                             const BigInt& order,
                             const BigInt& cofactor,
                             const OID& oid,
                             EC_Group_Source source) :
      m_curve(p, a, b),
      m_base_point(m_curve, g_x, g_y),
      m_g_x(g_x),
      m_g_y(g_y),
      m_order(order),
      m_cofactor(cofactor),
      m_mod_order(order),
      m_base_mult(m_base_point, m_mod_order),
      m_oid(oid),
      m_p_bits(p.bits()),
      m_order_bits(order.bits()),
      m_order_bytes((m_order_bits + 7) / 8),
      m_a_is_minus_3(a == p - 3),
      m_a_is_zero(a.is_zero()),
      m_has_cofactor(m_cofactor != 1),
      m_source(source) {}

bool EC_Group_Data::params_match(const BigInt& p,
                                 const BigInt& a,
                                 const BigInt& b,
                                 const BigInt& g_x,
                                 const BigInt& g_y,
                                 const BigInt& order,
                                 const BigInt& cofactor) const {
   return (this->p() == p && this->a() == a && this->b() == b && this->order() == order &&
           this->cofactor() == cofactor && this->g_x() == g_x && this->g_y() == g_y);
}

bool EC_Group_Data::params_match(const EC_Group_Data& other) const {
   return params_match(other.p(), other.a(), other.b(), other.g_x(), other.g_y(), other.order(), other.cofactor());
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bytes_with_trunc(std::span<const uint8_t> bytes) const {
   auto bn = BigInt::from_bytes_with_max_bits(bytes.data(), bytes.size(), m_order_bits);
   return std::make_unique<EC_Scalar_Data>(mod_order(bn));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bytes_mod_order(std::span<const uint8_t> bytes) const {
   BOTAN_ARG_CHECK(bytes.size() <= 2 * order_bytes(), "Input too large");
   return std::make_unique<EC_Scalar_Data>(mod_order(BigInt(bytes)));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_random(RandomNumberGenerator& rng) const {
   return std::make_unique<EC_Scalar_Data>(BigInt::random_integer(rng, BigInt::one(), m_order));
}

bool EC_Group_Data::scalar_is_zero(const EC_Scalar_Data& s) const {
   return s.value().is_zero();
}

bool EC_Group_Data::scalar_is_eq(const EC_Scalar_Data& x, const EC_Scalar_Data& y) const {
   return x.value() == y.value();
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_zero() const {
   return std::make_unique<EC_Scalar_Data>(BigInt::zero());
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_one() const {
   return std::make_unique<EC_Scalar_Data>(BigInt::one());
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_invert(const EC_Scalar_Data& s) const {
   return std::make_unique<EC_Scalar_Data>(inverse_mod_order(s.value()));
}

void EC_Group_Data::scalar_assign(EC_Scalar_Data& x, const EC_Scalar_Data& y) const {
   x.set_value(y.value());
}

void EC_Group_Data::scalar_square_self(EC_Scalar_Data& s) const {
   s.set_value(square_mod_order(s.value()));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_negate(const EC_Scalar_Data& s) const {
   return std::make_unique<EC_Scalar_Data>(mod_order(-s.value()));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_add(const EC_Scalar_Data& a, const EC_Scalar_Data& b) const {
   return std::make_unique<EC_Scalar_Data>(mod_order(a.value() + b.value()));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_sub(const EC_Scalar_Data& a, const EC_Scalar_Data& b) const {
   return std::make_unique<EC_Scalar_Data>(mod_order(a.value() - b.value()));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_mul(const EC_Scalar_Data& a, const EC_Scalar_Data& b) const {
   return std::make_unique<EC_Scalar_Data>(multiply_mod_order(a.value(), b.value()));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bigint(const BigInt& bn) const {
   // Assumed to have been already checked as in range
   return std::make_unique<EC_Scalar_Data>(bn);
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::gk_x_mod_order(const EC_Scalar_Data& scalar,
                                                              RandomNumberGenerator& rng,
                                                              std::vector<BigInt>& ws) const {
   const auto pt = m_base_mult.mul(scalar.value(), rng, m_order, ws);

   if(pt.is_zero()) {
      return scalar_zero();
   } else {
      return std::make_unique<EC_Scalar_Data>(mod_order(pt.get_affine_x()));
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_deserialize(std::span<const uint8_t> bytes) {
   if(bytes.size() != m_order_bytes) {
      return nullptr;
   }

   BigInt r(bytes.data(), bytes.size());

   if(r.is_zero() || r >= m_order) {
      return nullptr;
   }

   return std::make_unique<EC_Scalar_Data>(std::move(r));
}

void EC_Group_Data::scalar_serialize_to(const EC_Scalar_Data& s, std::span<uint8_t> bytes) const {
   BOTAN_ARG_CHECK(bytes.size() == m_order_bytes, "Invalid output length");
   s.value().serialize_to(bytes);
}

}  // namespace Botan
