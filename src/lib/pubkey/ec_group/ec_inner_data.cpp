/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_inner_data.h>

#include <botan/internal/ec_inner_bn.h>

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   #include <botan/internal/ec_h2c.h>
#endif

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
   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), mod_order(bn));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bytes_mod_order(std::span<const uint8_t> bytes) const {
   BOTAN_ARG_CHECK(bytes.size() <= 2 * order_bytes(), "Input too large");
   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), mod_order(BigInt(bytes)));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_random(RandomNumberGenerator& rng) const {
   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), BigInt::random_integer(rng, BigInt::one(), m_order));
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_zero() const {
   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), BigInt::zero());
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_one() const {
   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), BigInt::one());
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bigint(const BigInt& bn) const {
   // Assumed to have been already checked as in range
   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), bn);
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::gk_x_mod_order(const EC_Scalar_Data& scalar,
                                                              RandomNumberGenerator& rng,
                                                              std::vector<BigInt>& ws) const {
   const auto& bn = EC_Scalar_Data_BN::checked_ref(scalar);
   const auto pt = m_base_mult.mul(bn.value(), rng, m_order, ws);

   if(pt.is_zero()) {
      return scalar_zero();
   } else {
      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), mod_order(pt.get_affine_x()));
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

   return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), std::move(r));
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_deserialize(std::span<const uint8_t> bytes) const {
   try {
      auto pt = Botan::OS2ECP(bytes.data(), bytes.size(), curve());
      return std::make_unique<EC_AffinePoint_Data_BN>(shared_from_this(), std::move(pt));
   } catch(...) {
      return nullptr;
   }
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_hash_to_curve_ro(std::string_view hash_fn,
                                                                           std::span<const uint8_t> input,
                                                                           std::span<const uint8_t> domain_sep) const {
#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   auto pt = hash_to_curve_sswu(*this, hash_fn, input, domain_sep, true);
   return std::make_unique<EC_AffinePoint_Data_BN>(shared_from_this(), std::move(pt));
#else
   BOTAN_UNUSED(hash_fn, input, domain_sep);
   throw Not_Implemented("Hashing to curve not available in this build");
#endif
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_hash_to_curve_nu(std::string_view hash_fn,
                                                                           std::span<const uint8_t> input,
                                                                           std::span<const uint8_t> domain_sep) const {
#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   auto pt = hash_to_curve_sswu(*this, hash_fn, input, domain_sep, false);
   return std::make_unique<EC_AffinePoint_Data_BN>(shared_from_this(), std::move(pt));
#else
   BOTAN_UNUSED(hash_fn, input, domain_sep);
   throw Not_Implemented("Hashing to curve not available in this build");
#endif
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_g_mul(const EC_Scalar_Data& scalar,
                                                                RandomNumberGenerator& rng,
                                                                std::vector<BigInt>& ws) const {
   const auto& group = scalar.group();
   const auto& bn = EC_Scalar_Data_BN::checked_ref(scalar);
   auto pt = group->blinded_base_point_multiply(bn.value(), rng, ws);
   return std::make_unique<EC_AffinePoint_Data_BN>(shared_from_this(), std::move(pt));
}

std::unique_ptr<EC_Mul2Table_Data> EC_Group_Data::make_mul2_table(const EC_AffinePoint_Data& h) const {
   EC_AffinePoint_Data_BN g(shared_from_this(), this->base_point());
   return std::make_unique<EC_Mul2Table_Data_BN>(g, h);
}

}  // namespace Botan
