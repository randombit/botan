/*
* ECGDSA (BSI-TR-03111, version 2.0)
* (C) 2016 René Korthaus
* (C) 2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecgdsa.h>

#include <botan/internal/keypair.h>
#include <botan/internal/pk_ops_impl.h>

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
      ECGDSA_Signature_Operation(const ECGDSA_PrivateKey& ecgdsa, PK_Signature_Options& options) :
            PK_Ops::Signature_with_Hash(options), m_group(ecgdsa.domain()), m_x(ecgdsa._private_key()) {}

      std::vector<uint8_t> raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) override;

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      const EC_Group m_group;
      const EC_Scalar m_x;
      std::vector<BigInt> m_ws;
};

AlgorithmIdentifier ECGDSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "ECGDSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::vector<uint8_t> ECGDSA_Signature_Operation::raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) {
   const auto m = EC_Scalar::from_bytes_with_trunc(m_group, msg);

   const auto k = EC_Scalar::random(m_group, rng);

   const auto r = EC_Scalar::gk_x_mod_order(k, rng, m_ws);

   const auto s = m_x * ((k * r) - m);

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero()) {
      throw Internal_Error("During ECGDSA signature generated zero r/s");
   }

   return EC_Scalar::serialize_pair(r, s);
}

/**
* ECGDSA verification operation
*/
class ECGDSA_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      ECGDSA_Verification_Operation(const ECGDSA_PublicKey& ecgdsa, PK_Signature_Options& options) :
            PK_Ops::Verification_with_Hash(options), m_group(ecgdsa.domain()), m_gy_mul(ecgdsa._public_key()) {}

      ECGDSA_Verification_Operation(const ECGDSA_PublicKey& ecgdsa, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(alg_id, "ECGDSA"),
            m_group(ecgdsa.domain()),
            m_gy_mul(ecgdsa._public_key()) {}

      bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) override;

   private:
      const EC_Group m_group;
      const EC_Group::Mul2Table m_gy_mul;
};

bool ECGDSA_Verification_Operation::verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) {
   if(auto rs = EC_Scalar::deserialize_pair(m_group, sig)) {
      const auto& [r, s] = rs.value();

      if(r.is_nonzero() && s.is_nonzero()) {
         const auto m = EC_Scalar::from_bytes_with_trunc(m_group, msg);

         const auto w = r.invert();

         // Check if r == x_coord(g*w*m + y*w*s) % n
         return m_gy_mul.mul2_vartime_x_mod_order_eq(r, w, m, s);
      }
   }

   return false;
}

}  // namespace

std::unique_ptr<Private_Key> ECGDSA_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ECGDSA_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Verification> ECGDSA_PublicKey::_create_verification_op(PK_Signature_Options& options) const {
   options.exclude_provider();
   return std::make_unique<ECGDSA_Verification_Operation>(*this, options);
}

std::unique_ptr<PK_Ops::Verification> ECGDSA_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECGDSA_Verification_Operation>(*this, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> ECGDSA_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                           PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);
   options.exclude_provider();
   return std::make_unique<ECGDSA_Signature_Operation>(*this, options);
}

}  // namespace Botan
