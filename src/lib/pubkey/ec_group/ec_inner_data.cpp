/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_inner_data.h>

#include <botan/der_enc.h>
#include <botan/internal/ec_inner_bn.h>
#include <botan/internal/ec_inner_pc.h>
#include <botan/internal/pcurves.h>
#include <botan/internal/point_mul.h>

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
      m_oid(oid),
      m_p_bits(p.bits()),
      m_order_bits(order.bits()),
      m_order_bytes((m_order_bits + 7) / 8),
      m_a_is_minus_3(a == p - 3),
      m_a_is_zero(a.is_zero()),
      m_has_cofactor(m_cofactor != 1),
      m_order_is_less_than_p(m_order < p),
      m_source(source) {
   if(!m_oid.empty()) {
      DER_Encoder der(m_der_named_curve);
      der.encode(m_oid);

      if(const auto id = PCurve::PrimeOrderCurveId::from_oid(m_oid)) {
         m_pcurve = PCurve::PrimeOrderCurve::from_id(*id);
         // still possibly null, if the curve is supported in general but not
         // available in the build
      }
   }

   if(!m_pcurve) {
      m_base_mult = std::make_unique<EC_Point_Base_Point_Precompute>(m_base_point, m_mod_order);
   }
}

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

void EC_Group_Data::set_oid(const OID& oid) {
   BOTAN_ARG_CHECK(!oid.empty(), "OID should be set");
   BOTAN_STATE_CHECK(m_oid.empty() && m_der_named_curve.empty());
   m_oid = oid;

   DER_Encoder der(m_der_named_curve);
   der.encode(m_oid);
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bytes_with_trunc(std::span<const uint8_t> bytes) const {
   const size_t bit_length = 8 * bytes.size();

   if(bit_length < order_bits()) {
      // No shifting required, but might still need to reduce by modulus
      return this->scalar_from_bytes_mod_order(bytes);
   } else {
      const size_t shift = bit_length - order_bits();

      const size_t new_length = bytes.size() - (shift / 8);
      const size_t bit_shift = shift % 8;

      if(bit_shift == 0) {
         // Easy case just read different bytes
         return this->scalar_from_bytes_mod_order(bytes.first(new_length));
      } else {
         std::vector<uint8_t> sbytes(new_length);

         uint8_t carry = 0;
         for(size_t i = 0; i != new_length; ++i) {
            const uint8_t w = bytes[i];
            sbytes[i] = (w >> bit_shift) | carry;
            carry = w << (8 - bit_shift);
         }

         return this->scalar_from_bytes_mod_order(sbytes);
      }
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bytes_mod_order(std::span<const uint8_t> bytes) const {
   if(bytes.size() >= 2 * order_bytes()) {
      return {};
   }

   if(m_pcurve) {
      if(auto s = m_pcurve->scalar_from_wide_bytes(bytes)) {
         return std::make_unique<EC_Scalar_Data_PC>(shared_from_this(), std::move(*s));
      } else {
         return {};
      }
   } else {
      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), mod_order(BigInt(bytes)));
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_random(RandomNumberGenerator& rng) const {
   if(m_pcurve) {
      return std::make_unique<EC_Scalar_Data_PC>(shared_from_this(), m_pcurve->random_scalar(rng));
   } else {
      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(),
                                                 BigInt::random_integer(rng, BigInt::one(), m_order));
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_zero() const {
   if(m_pcurve) {
      return std::make_unique<EC_Scalar_Data_PC>(shared_from_this(), m_pcurve->scalar_zero());
   } else {
      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), BigInt::zero());
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_one() const {
   if(m_pcurve) {
      return std::make_unique<EC_Scalar_Data_PC>(shared_from_this(), m_pcurve->scalar_one());
   } else {
      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), BigInt::one());
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_from_bigint(const BigInt& bn) const {
   if(bn <= 0 || bn >= m_order) {
      return {};
   }

   if(m_pcurve) {
      return this->scalar_deserialize(bn.serialize(m_order_bytes));
   } else {
      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), bn);
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::gk_x_mod_order(const EC_Scalar_Data& scalar,
                                                              RandomNumberGenerator& rng,
                                                              std::vector<BigInt>& ws) const {
   if(m_pcurve) {
      const auto& k = EC_Scalar_Data_PC::checked_ref(scalar);
      auto gk_x_mod_order = m_pcurve->base_point_mul_x_mod_order(k.value(), rng);
      return std::make_unique<EC_Scalar_Data_PC>(shared_from_this(), gk_x_mod_order);
   } else {
      const auto& k = EC_Scalar_Data_BN::checked_ref(scalar);
      BOTAN_STATE_CHECK(m_base_mult != nullptr);
      const auto pt = m_base_mult->mul(k.value(), rng, m_order, ws);

      if(pt.is_zero()) {
         return scalar_zero();
      } else {
         return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), mod_order(pt.get_affine_x()));
      }
   }
}

std::unique_ptr<EC_Scalar_Data> EC_Group_Data::scalar_deserialize(std::span<const uint8_t> bytes) const {
   if(bytes.size() != m_order_bytes) {
      return nullptr;
   }

   if(m_pcurve) {
      if(auto s = m_pcurve->deserialize_scalar(bytes)) {
         return std::make_unique<EC_Scalar_Data_PC>(shared_from_this(), *s);
      } else {
         return nullptr;
      }
   } else {
      BigInt r(bytes);

      if(r.is_zero() || r >= m_order) {
         return nullptr;
      }

      return std::make_unique<EC_Scalar_Data_BN>(shared_from_this(), std::move(r));
   }
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_deserialize(std::span<const uint8_t> bytes) const {
   try {
      if(m_pcurve) {
         if(auto pt = m_pcurve->deserialize_point(bytes)) {
            return std::make_unique<EC_AffinePoint_Data_PC>(shared_from_this(), std::move(*pt));
         } else {
            return nullptr;
         }
      } else {
         auto pt = Botan::OS2ECP(bytes.data(), bytes.size(), curve());
         return std::make_unique<EC_AffinePoint_Data_BN>(shared_from_this(), std::move(pt));
      }
   } catch(...) {
      return nullptr;
   }
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_hash_to_curve_ro(std::string_view hash_fn,
                                                                           std::span<const uint8_t> input,
                                                                           std::span<const uint8_t> domain_sep) const {
   if(m_pcurve) {
      auto pt = m_pcurve->hash_to_curve_ro(hash_fn, input, domain_sep);
      return std::make_unique<EC_AffinePoint_Data_PC>(shared_from_this(), pt.to_affine());
   } else {
      throw Not_Implemented("Hash to curve is not implemented for this curve");
   }
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_hash_to_curve_nu(std::string_view hash_fn,
                                                                           std::span<const uint8_t> input,
                                                                           std::span<const uint8_t> domain_sep) const {
   if(m_pcurve) {
      auto pt = m_pcurve->hash_to_curve_nu(hash_fn, input, domain_sep);
      return std::make_unique<EC_AffinePoint_Data_PC>(shared_from_this(), std::move(pt));
   } else {
      throw Not_Implemented("Hash to curve is not implemented for this curve");
   }
}

std::unique_ptr<EC_AffinePoint_Data> EC_Group_Data::point_g_mul(const EC_Scalar_Data& scalar,
                                                                RandomNumberGenerator& rng,
                                                                std::vector<BigInt>& ws) const {
   if(m_pcurve) {
      const auto& k = EC_Scalar_Data_PC::checked_ref(scalar);
      auto pt = m_pcurve->mul_by_g(k.value(), rng).to_affine();
      return std::make_unique<EC_AffinePoint_Data_PC>(shared_from_this(), std::move(pt));
   } else {
      const auto& group = scalar.group();
      const auto& bn = EC_Scalar_Data_BN::checked_ref(scalar);

      BOTAN_STATE_CHECK(group->m_base_mult != nullptr);
      auto pt = group->m_base_mult->mul(bn.value(), rng, m_order, ws);
      return std::make_unique<EC_AffinePoint_Data_BN>(shared_from_this(), std::move(pt));
   }
}

std::unique_ptr<EC_Mul2Table_Data> EC_Group_Data::make_mul2_table(const EC_AffinePoint_Data& h) const {
   if(m_pcurve) {
      EC_AffinePoint_Data_PC g(shared_from_this(), m_pcurve->generator());
      return std::make_unique<EC_Mul2Table_Data_PC>(g, h);
   } else {
      EC_AffinePoint_Data_BN g(shared_from_this(), this->base_point());
      return std::make_unique<EC_Mul2Table_Data_BN>(g, h);
   }
}

}  // namespace Botan
