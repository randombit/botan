/*
* ECGDSA (BSI-TR-03111, version 2.0)
* (C) 2016 René Korthaus
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecgdsa.h>

#include <botan/reducer.h>
#include <botan/internal/keypair.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>

namespace Botan {

std::unique_ptr<Public_Key> ECGDSA_PrivateKey::public_key() const {
   return std::make_unique<ECGDSA_PublicKey>(domain(), public_point());
}

bool ECGDSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
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
* ECGDSA signature operation
*/
class ECGDSA_Signature_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      ECGDSA_Signature_Operation(const ECGDSA_PrivateKey& ecgdsa, std::string_view emsa) :
            PK_Ops::Signature_with_Hash(emsa), m_group(ecgdsa.domain()), m_x(ecgdsa.private_value()) {}

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len, RandomNumberGenerator& rng) override;

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      const EC_Group m_group;
      const BigInt m_x;
      std::vector<BigInt> m_ws;
};

AlgorithmIdentifier ECGDSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "ECGDSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

secure_vector<uint8_t> ECGDSA_Signature_Operation::raw_sign(const uint8_t msg[],
                                                            size_t msg_len,
                                                            RandomNumberGenerator& rng) {
   const BigInt m = BigInt::from_bytes_with_max_bits(msg, msg_len, m_group.get_order_bits());

   const BigInt k = m_group.random_scalar(rng);

   const BigInt r = m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

   const BigInt kr = m_group.multiply_mod_order(k, r);

   const BigInt s = m_group.multiply_mod_order(m_x, kr - m);

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero()) {
      throw Internal_Error("During ECGDSA signature generated zero r/s");
   }

   return BigInt::encode_fixed_length_int_pair(r, s, m_group.get_order_bytes());
}

/**
* ECGDSA verification operation
*/
class ECGDSA_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      ECGDSA_Verification_Operation(const ECGDSA_PublicKey& ecgdsa, std::string_view padding) :
            PK_Ops::Verification_with_Hash(padding),
            m_group(ecgdsa.domain()),
            m_gy_mul(m_group.get_base_point(), ecgdsa.public_point()) {}

      ECGDSA_Verification_Operation(const ECGDSA_PublicKey& ecgdsa, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(alg_id, "ECGDSA"),
            m_group(ecgdsa.domain()),
            m_gy_mul(m_group.get_base_point(), ecgdsa.public_point()) {}

      bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

   private:
      const EC_Group m_group;
      const EC_Point_Multi_Point_Precompute m_gy_mul;
};

bool ECGDSA_Verification_Operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) {
   if(sig_len != m_group.get_order_bytes() * 2) {
      return false;
   }

   const BigInt e = BigInt::from_bytes_with_max_bits(msg, msg_len, m_group.get_order_bits());

   const BigInt r(sig, sig_len / 2);
   const BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
      return false;
   }

   const BigInt w = m_group.inverse_mod_order(r);

   const BigInt u1 = m_group.multiply_mod_order(e, w);
   const BigInt u2 = m_group.multiply_mod_order(s, w);
   const EC_Point R = m_gy_mul.multi_exp(u1, u2);

   if(R.is_zero()) {
      return false;
   }

   const BigInt v = m_group.mod_order(R.get_affine_x());
   return (v == r);
}

}  // namespace

std::unique_ptr<Private_Key> ECGDSA_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ECGDSA_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Verification> ECGDSA_PublicKey::create_verification_op(std::string_view params,
                                                                               std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECGDSA_Verification_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> ECGDSA_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECGDSA_Verification_Operation>(*this, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> ECGDSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                          std::string_view params,
                                                                          std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECGDSA_Signature_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
