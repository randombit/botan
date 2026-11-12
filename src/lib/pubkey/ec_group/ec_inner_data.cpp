/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_inner_data.h>

#include <botan/der_enc.h>
#include <botan/internal/barrett.h>
#include <botan/internal/fmt.h>
#include <algorithm>

#if defined(BOTAN_HAS_XMD)
   #include <botan/hash.h>
   #include <botan/internal/xmd.h>
#endif

namespace Botan {

EC_Group_Data::~EC_Group_Data() = default;

EC_Group_Data::EC_Group_Data(const BigInt& p,
                             const BigInt& a,
                             const BigInt& b,
                             const BigInt& g_x,
                             const BigInt& g_y,
                             const BigInt& order,
                             const OID& oid,
                             EC_Group_Source source) :
      m_p(p),
      m_a(a),
      m_b(b),
      m_g_x(g_x),
      m_g_y(g_y),
      m_order(order),
      m_oid(oid),
      m_p_words(p.sig_words()),
      m_p_bits(p.bits()),
      m_order_bits(order.bits()),
      m_order_bytes((m_order_bits + 7) / 8),
      m_source(source) {
   BOTAN_ARG_CHECK(m_oid.has_value(), "EC_Group OID must be set");

   // Verify the generator (x, y) satisfies y^2 = x^3 + a*x + b (mod p)
   const auto mod_p = Barrett_Reduction::for_public_modulus(p);
   const BigInt y2 = mod_p.square(g_y);
   const BigInt x3_ax_b = mod_p.reduce(mod_p.cube(g_x) + mod_p.multiply(a, g_x) + b);
   if(y2 != x3_ax_b) {
      throw Invalid_Argument("EC_Group generator is not on the curve");
   }

   DER_Encoder der(m_der_named_curve);
   der.encode(m_oid);

   if(const auto name = m_oid.registered_name()) {
      if(auto pcurve = PCurve::PrimeOrderCurve::for_named_curve(*name)) {
         const bool same_params = [&]() {
            if(m_source == EC_Group_Source::Builtin) {
               return true;
            }

            if(const auto group_oid = OID::from_name(*name)) {
               if(const auto group_info = EC_Group::EC_group_info(*group_oid)) {
                  return group_info->params_match(p, a, b, g_x, g_y, order);
               }
            }

            return false;
         }();

         if(same_params) {
            m_pcurve = std::move(pcurve);
            m_engine = EC_Group_Engine::Optimized;
         }
      }
   }

   // Try a generic pcurves instance
   if(!m_pcurve) {
      m_pcurve = PCurve::PrimeOrderCurve::from_params(p, a, b, g_x, g_y, order);
      if(m_pcurve) {
         m_engine = EC_Group_Engine::Generic;
      }
      // possibly still null here, if parameters unsuitable or if the
      // pcurves_generic module wasn't included in the build
   }

   if(!m_pcurve) {
      throw Not_Implemented(fmt("EC_Group the group {} is not supported in this build configuration", oid.to_string()));
   }
}

std::shared_ptr<EC_Group_Data> EC_Group_Data::create(const BigInt& p,
                                                     const BigInt& a,
                                                     const BigInt& b,
                                                     const BigInt& g_x,
                                                     const BigInt& g_y,
                                                     const BigInt& order,
                                                     const OID& oid,
                                                     EC_Group_Source source) {
   return std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, oid, source);
}

bool EC_Group_Data::params_match(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& g_x, const BigInt& g_y, const BigInt& order) const {
   if(p != this->p()) {
      return false;
   }
   if(a != this->a()) {
      return false;
   }
   if(b != this->b()) {
      return false;
   }
   if(order != this->order()) {
      return false;
   }
   if(g_x != this->g_x()) {
      return false;
   }
   if(g_y != this->g_y()) {
      return false;
   }

   return true;
}

bool EC_Group_Data::params_match(
   const BigInt& p, const BigInt& a, const BigInt& b, std::span<const uint8_t> base_pt, const BigInt& order) const {
   if(p != this->p()) {
      return false;
   }
   if(a != this->a()) {
      return false;
   }
   if(b != this->b()) {
      return false;
   }
   if(order != this->order()) {
      return false;
   }

   const size_t field_len = this->p_bytes();

   if(base_pt.size() == 1 + field_len && (base_pt[0] == 0x02 || base_pt[0] == 0x03)) {
      // compressed

      const auto g_x = m_g_x.serialize(field_len);
      const auto g_y = m_g_y.is_odd();

      const auto sec1_x = base_pt.subspan(1, field_len);
      const bool sec1_y = (base_pt[0] == 0x03);

      if(!std::ranges::equal(sec1_x, g_x)) {
         return false;
      }

      if(sec1_y != g_y) {
         return false;
      }

      return true;
   } else if(base_pt.size() == 1 + 2 * field_len && base_pt[0] == 0x04) {
      const auto g_x = m_g_x.serialize(field_len);
      const auto g_y = m_g_y.serialize(field_len);

      const auto sec1_x = base_pt.subspan(1, field_len);
      const auto sec1_y = base_pt.subspan(1 + field_len, field_len);

      if(!std::ranges::equal(sec1_x, g_x)) {
         return false;
      }

      if(!std::ranges::equal(sec1_y, g_y)) {
         return false;
      }

      return true;
   } else {
      throw Decoding_Error("Invalid base point encoding in explicit group");
   }
}

bool EC_Group_Data::params_match(const EC_Group_Data& other) const {
   return params_match(other.p(), other.a(), other.b(), other.g_x(), other.g_y(), other.order());
}

std::function<void(std::span<uint8_t>)> h2c_expand_message(std::string_view hash_fn,
                                                           size_t order_bits,
                                                           std::span<const uint8_t> input,
                                                           std::span<const uint8_t> domain_sep) {
   /*
   * This could be extended to support expand_message_xof or a MHF like Argon2
   */

   if(hash_fn.starts_with("SHAKE")) {
      throw Not_Implemented("Hash to curve currently does not support expand_message_xof");
   }

#if defined(BOTAN_HAS_XMD)
   // Here we capture the HashFunction by shared_ptr because it will be owned by
   // the returned std::function
   const std::shared_ptr<HashFunction> hash = HashFunction::create_or_throw(hash_fn);

   /*
   * RFC 9380 Section 5.3.1: "The number of bits output by H MUST be b >= 2 * k,
   * where k is the target security level in bits", as this "ensures k-bit
   * collision resistance". Checking the hash's collision resistance estimate
   * covers this, and also rejects hashes with known collision attacks. The
   * target level is capped at 256 since the RFC 9380 suites for P-521 use k = 256.
   */
   const size_t k = std::min<size_t>((order_bits + 1) / 2, 256);

   if(hash->security_level() < k) {
      throw Invalid_Argument(fmt("Hash {} is too weak for use with a {} bit group", hash->name(), order_bits));
   }

   return [hash, input, domain_sep](std::span<uint8_t> uniform_bytes) {
      expand_message_xmd(*hash, uniform_bytes, input, domain_sep);
   };
#else
   BOTAN_UNUSED(order_bits, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented due to XMD being disabled");
#endif
}

bool EC_Group_Data::hash_to_curve_supported(std::string_view hash_fn) const {
#if defined(BOTAN_HAS_XMD)
   if(!m_pcurve->supports_hash_to_curve()) {
      return false;
   }

   // Consistent with h2c_expand_message; XOF based expansion is not implemented
   if(hash_fn.starts_with("SHAKE")) {
      return false;
   }

   auto hash = HashFunction::create(hash_fn);
   if(hash == nullptr) {
      return false;
   }

   // The same hash strength requirement enforced by h2c_expand_message
   const size_t k = std::min<size_t>((order_bits() + 1) / 2, 256);
   if(hash->security_level() < k) {
      return false;
   }

   // The same requirements enforced by expand_message_xmd
   return hash->hash_block_size() > 0 && hash->output_length() <= hash->hash_block_size();
#else
   BOTAN_UNUSED(hash_fn);
   return false;
#endif
}

EC_AffinePoint_Data::EC_AffinePoint_Data(std::shared_ptr<const EC_Group_Data> group,
                                         PCurve::PrimeOrderCurve::AffinePoint pt) :
      m_group(std::move(group)), m_pt(std::move(pt)) {
   const auto& pcurve = m_group->pcurve();

   if(!pcurve.affine_point_is_identity(m_pt)) {
      m_xy.resize(1 + 2 * pcurve.field_element_bytes());
      pcurve.serialize_point(m_xy, m_pt);
   }
}

}  // namespace Botan
