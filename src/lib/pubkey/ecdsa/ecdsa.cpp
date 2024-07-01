/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010,2015,2016,2018,2024 Jack Lloyd
*     2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecdsa.h>

#include <botan/internal/keypair.h>
#include <botan/internal/pk_ops_impl.h>

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   #include <botan/internal/rfc6979.h>
#endif

namespace Botan {

namespace {

EC_Point recover_ecdsa_public_key(
   const EC_Group& group, const std::vector<uint8_t>& msg, const BigInt& r, const BigInt& s, uint8_t v) {
   if(group.get_cofactor() != 1) {
      throw Invalid_Argument("ECDSA public key recovery only supported for prime order groups");
   }

   if(v >= 4) {
      throw Invalid_Argument("Unexpected v param for ECDSA public key recovery");
   }

   const BigInt& group_order = group.get_order();

   if(r <= 0 || r >= group_order || s <= 0 || s >= group_order) {
      throw Invalid_Argument("Out of range r/s cannot recover ECDSA public key");
   }

   const uint8_t y_odd = v % 2;
   const uint8_t add_order = v >> 1;
   const size_t p_bytes = group.get_p_bytes();

   try {
      BigInt x = r + add_order * group_order;

      std::vector<uint8_t> X(p_bytes + 1);

      X[0] = 0x02 | y_odd;
      x.serialize_to(std::span{X}.subspan(1));

      if(auto R = EC_AffinePoint::deserialize(group, X)) {
         // Compute r_inv * (-eG + s*R)
         const auto ne = EC_Scalar::from_bytes_with_trunc(group, msg).negate();
         const auto ss = EC_Scalar::from_bigint(group, s);

         const auto r_inv = EC_Scalar::from_bigint(group, r).invert();

         EC_Group::Mul2Table GR_mul(R.value());
         if(auto egsr = GR_mul.mul2_vartime(ne * r_inv, ss * r_inv)) {
            return egsr->to_legacy_point();
         }
      }
   } catch(...) {
      // continue on and throw
   }

   throw Decoding_Error("Failed to recover ECDSA public key from signature/msg pair");
}

}  // namespace

ECDSA_PublicKey::ECDSA_PublicKey(
   const EC_Group& group, const std::vector<uint8_t>& msg, const BigInt& r, const BigInt& s, uint8_t v) :
      EC_PublicKey(group, recover_ecdsa_public_key(group, msg, r, s, v)) {}

std::unique_ptr<Private_Key> ECDSA_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ECDSA_PrivateKey>(rng, domain());
}

uint8_t ECDSA_PublicKey::recovery_param(const std::vector<uint8_t>& msg, const BigInt& r, const BigInt& s) const {
   for(uint8_t v = 0; v != 4; ++v) {
      try {
         EC_Point R = recover_ecdsa_public_key(this->domain(), msg, r, s, v);

         if(R == this->public_point()) {
            return v;
         }
      } catch(Decoding_Error&) {
         // try the next v
      }
   }

   throw Internal_Error("Could not determine ECDSA recovery parameter");
}

std::unique_ptr<Public_Key> ECDSA_PrivateKey::public_key() const {
   return std::make_unique<ECDSA_PublicKey>(domain(), public_point());
}

bool ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!EC_PrivateKey::check_key(rng, strong)) {
      return false;
   }

   if(!strong) {
      return true;
   }

   return KeyPair::signature_consistency_check(rng, *this, "SHA-256");
}

namespace {

/**
* ECDSA signature operation
*/
class ECDSA_Signature_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa, std::string_view padding, RandomNumberGenerator& rng) :
            PK_Ops::Signature_with_Hash(padding),
            m_group(ecdsa.domain()),
            m_x(EC_Scalar::from_bigint(m_group, ecdsa.private_value())),
            m_b(EC_Scalar::random(m_group, rng)),
            m_b_inv(m_b.invert()) {
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         m_rfc6979 = std::make_unique<RFC6979_Nonce_Generator>(
            this->rfc6979_hash_function(), m_group.get_order(), ecdsa.private_value());
#endif
      }

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len, RandomNumberGenerator& rng) override;

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      const EC_Group m_group;
      const EC_Scalar m_x;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
      std::unique_ptr<RFC6979_Nonce_Generator> m_rfc6979;
#endif

      std::vector<BigInt> m_ws;

      EC_Scalar m_b;
      EC_Scalar m_b_inv;
};

AlgorithmIdentifier ECDSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "ECDSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

secure_vector<uint8_t> ECDSA_Signature_Operation::raw_sign(const uint8_t msg[],
                                                           size_t msg_len,
                                                           RandomNumberGenerator& rng) {
   const auto m = EC_Scalar::from_bytes_with_trunc(m_group, std::span{msg, msg_len});

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   const auto k = m_rfc6979->nonce_for(m_group, m);
#else
   const auto k = EC_Scalar::random(m_group, rng);
#endif

   const auto r = EC_Scalar::gk_x_mod_order(k, rng, m_ws);

   const auto k_inv = k.invert();

   /*
   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
   */
   m_b.square_self();
   m_b_inv.square_self();

   const auto xr_m = ((m_x * m_b) * r) + (m * m_b);

   const auto s = (k_inv * xr_m) * m_b_inv;

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero()) {
      throw Internal_Error("During ECDSA signature generated zero r/s");
   }

   return EC_Scalar::serialize_pair<secure_vector<uint8_t>>(r, s);
}

/**
* ECDSA verification operation
*/
class ECDSA_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa, std::string_view padding) :
            PK_Ops::Verification_with_Hash(padding), m_group(ecdsa.domain()), m_gy_mul(m_group, ecdsa.public_point()) {}

      ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(alg_id, "ECDSA", true),
            m_group(ecdsa.domain()),
            m_gy_mul(m_group, ecdsa.public_point()) {}

      bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

   private:
      const EC_Group m_group;
      const EC_Group::Mul2Table m_gy_mul;
};

bool ECDSA_Verification_Operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) {
   if(auto rs = EC_Scalar::deserialize_pair(m_group, std::span{sig, sig_len})) {
      const auto& [r, s] = rs.value();

      if(r.is_nonzero() && s.is_nonzero()) {
         const auto m = EC_Scalar::from_bytes_with_trunc(m_group, std::span{msg, msg_len});

         const auto w = s.invert();

         if(const auto v = m_gy_mul.mul2_vartime_x_mod_order(w, m, r)) {
            return (v == r);
         }
      }
   }

   return false;
}

}  // namespace

std::unique_ptr<PK_Ops::Verification> ECDSA_PublicKey::create_verification_op(std::string_view params,
                                                                              std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECDSA_Verification_Operation>(*this, params);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> ECDSA_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECDSA_Verification_Operation>(*this, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> ECDSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                         std::string_view params,
                                                                         std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECDSA_Signature_Operation>(*this, params, rng);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
