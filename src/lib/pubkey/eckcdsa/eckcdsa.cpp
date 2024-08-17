/*
* ECKCDSA (ISO/IEC 14888-3:2006/Cor.2:2009)
* (C) 2016 René Korthaus, Sirrix AG
* (C) 2018,2024 Jack Lloyd
* (C) 2023 Philippe Lieser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eckcdsa.h>

#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keypair.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::unique_ptr<Public_Key> ECKCDSA_PrivateKey::public_key() const {
   return std::make_unique<ECKCDSA_PublicKey>(domain(), public_point());
}

bool ECKCDSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!EC_PrivateKey::check_key(rng, strong)) {
      return false;
   }

   if(!strong) {
      return true;
   }

   return KeyPair::signature_consistency_check(rng, *this, "SHA-256");
}

namespace {

std::unique_ptr<HashFunction> eckcdsa_signature_hash(std::string_view padding) {
   if(auto hash = HashFunction::create(padding)) {
      return hash;
   }

   SCAN_Name req(padding);

   if(req.algo_name() == "EMSA1" && req.arg_count() == 1) {
      if(auto hash = HashFunction::create(req.arg(0))) {
         return hash;
      }
   }

   // intentionally not supporting Raw for ECKCDSA, we need to know
   // the length in advance which complicates the logic for Raw

   throw Algorithm_Not_Found(padding);
}

std::unique_ptr<HashFunction> eckcdsa_signature_hash(const AlgorithmIdentifier& alg_id) {
   const auto oid_info = split_on(alg_id.oid().to_formatted_string(), '/');

   if(oid_info.size() != 2 || oid_info[0] != "ECKCDSA") {
      throw Decoding_Error(fmt("Unexpected AlgorithmIdentifier OID {} in association with ECKCDSA key", alg_id.oid()));
   }

   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected non-empty AlgorithmIdentifier parameters for ECKCDSA");
   }

   return HashFunction::create_or_throw(oid_info[1]);
}

std::vector<uint8_t> eckcdsa_prefix(const EC_AffinePoint& point, size_t hash_block_size) {
   auto prefix = point.xy_bytes<std::vector<uint8_t>>();

   // Either truncate or zero-extend to match the hash block size
   prefix.resize(hash_block_size);

   return prefix;
}

/**
 * @brief Truncate hash output if needed.
 *
 * If the output length of the hash function exceeds the size of the group order,
 * ISO/IEC 14888-3:2018 specifies a truncation of the hash output
 * when calculating the witness R (the first part of the signature) and H.
 *
 * The truncation is specified as follows:
 *
 * R = I2BS(beta', BS2I(gamma, R) mod 2^beta')
 * H = I2BS(beta', BS2I(gamma, H) mod 2^beta')
 *
 * where
 * - gamma: the output bit-length of the hash-function
 * - beta: the bit-length of the prime number q (i.e. the group order size)
 * - beta' = 8 * ceil(beta / 8)
 *
 * This essentially means a truncation on the byte level
 * happens from the low side of the hash.
 *
 * @param[in,out] digest The hash output to potentially truncate.
 * @param[in] group_order_bytes Size of the group order.
 */
void truncate_hash_if_needed(std::vector<uint8_t>& digest, size_t group_order_bytes) {
   if(digest.size() > group_order_bytes) {
      const size_t bytes_to_truncate = digest.size() - group_order_bytes;
      digest.erase(digest.begin(), digest.begin() + bytes_to_truncate);
   }
}

/**
* ECKCDSA signature operation
*/
class ECKCDSA_Signature_Operation final : public PK_Ops::Signature {
   public:
      ECKCDSA_Signature_Operation(const ECKCDSA_PrivateKey& eckcdsa, const PK_Signature_Options& options) :
            m_group(eckcdsa.domain()),
            m_x(eckcdsa._private_key()),
            m_hash(eckcdsa_signature_hash(options.hash_function())),
            m_prefix(eckcdsa_prefix(eckcdsa._public_key(), m_hash->hash_block_size())),
            m_prefix_used(false) {}

      void update(std::span<const uint8_t> input) override {
         if(!m_prefix_used) {
            m_hash->update(m_prefix);
            m_prefix_used = true;
         }
         m_hash->update(input);
      }

      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         m_prefix_used = false;
         std::vector<uint8_t> digest = m_hash->final_stdvec();
         truncate_hash_if_needed(digest, m_group.get_order_bytes());
         return raw_sign(digest, rng);
      }

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::vector<uint8_t> raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng);

      const EC_Group m_group;
      const EC_Scalar m_x;
      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_prefix;
      std::vector<BigInt> m_ws;
      bool m_prefix_used;
};

AlgorithmIdentifier ECKCDSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "ECKCDSA/" + m_hash->name();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::vector<uint8_t> ECKCDSA_Signature_Operation::raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) {
   const auto k = EC_Scalar::random(m_group, rng);

   m_hash->update(EC_AffinePoint::g_mul(k, rng, m_ws).x_bytes());
   auto c = m_hash->final_stdvec();
   truncate_hash_if_needed(c, m_group.get_order_bytes());

   const auto r = c;

   xor_buf(c, msg);
   const auto w = EC_Scalar::from_bytes_mod_order(m_group, c);

   const auto s = m_x * (k - w);
   if(s.is_zero()) {
      throw Internal_Error("During ECKCDSA signature generation created zero s");
   }

   return concat(r, s.serialize());
}

/**
* ECKCDSA verification operation
*/
class ECKCDSA_Verification_Operation final : public PK_Ops::Verification {
   public:
      ECKCDSA_Verification_Operation(const ECKCDSA_PublicKey& eckcdsa, std::string_view padding) :
            m_group(eckcdsa.domain()),
            m_gy_mul(eckcdsa._public_key()),
            m_hash(eckcdsa_signature_hash(padding)),
            m_prefix(eckcdsa_prefix(eckcdsa._public_key(), m_hash->hash_block_size())),
            m_prefix_used(false) {}

      ECKCDSA_Verification_Operation(const ECKCDSA_PublicKey& eckcdsa, const AlgorithmIdentifier& alg_id) :
            m_group(eckcdsa.domain()),
            m_gy_mul(eckcdsa._public_key()),
            m_hash(eckcdsa_signature_hash(alg_id)),
            m_prefix(eckcdsa_prefix(eckcdsa._public_key(), m_hash->hash_block_size())),
            m_prefix_used(false) {}

      void update(std::span<const uint8_t> msg) override;

      bool is_valid_signature(std::span<const uint8_t> sig) override;

      std::string hash_function() const override { return m_hash->name(); }

   private:
      bool verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig);

      const EC_Group m_group;
      const EC_Group::Mul2Table m_gy_mul;
      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_prefix;
      bool m_prefix_used;
};

void ECKCDSA_Verification_Operation::update(std::span<const uint8_t> msg) {
   if(!m_prefix_used) {
      m_prefix_used = true;
      m_hash->update(m_prefix.data(), m_prefix.size());
   }
   m_hash->update(msg);
}

bool ECKCDSA_Verification_Operation::is_valid_signature(std::span<const uint8_t> sig) {
   m_prefix_used = false;
   std::vector<uint8_t> digest = m_hash->final_stdvec();
   truncate_hash_if_needed(digest, m_group.get_order_bytes());
   return verify(digest, sig);
}

bool ECKCDSA_Verification_Operation::verify(std::span<const uint8_t> msg, std::span<const uint8_t> sig) {
   const size_t order_bytes = m_group.get_order_bytes();

   const size_t size_r = std::min(msg.size(), order_bytes);
   if(sig.size() != size_r + order_bytes) {
      return false;
   }

   auto r = sig.first(size_r);

   if(auto s = EC_Scalar::deserialize(m_group, sig.last(order_bytes))) {
      std::vector<uint8_t> r_xor_e(r.size());
      xor_buf(r_xor_e, r, msg.first(size_r));

      const auto w = EC_Scalar::from_bytes_mod_order(m_group, r_xor_e);

      if(auto q = m_gy_mul.mul2_vartime(w, s.value())) {
         std::vector<uint8_t> v = m_hash->process<std::vector<uint8_t>>(q->x_bytes());
         truncate_hash_if_needed(v, m_group.get_order_bytes());
         return constant_time_compare(v, r);
      }
   }

   return false;
}

}  // namespace

std::unique_ptr<Private_Key> ECKCDSA_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ECKCDSA_PrivateKey>(rng, domain());
}

std::unique_ptr<PK_Ops::Verification> ECKCDSA_PublicKey::create_verification_op(std::string_view params,
                                                                                std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECKCDSA_Verification_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> ECKCDSA_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECKCDSA_Verification_Operation>(*this, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> ECKCDSA_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                            const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   if(!options.using_provider()) {
      return std::make_unique<ECKCDSA_Signature_Operation>(*this, options);
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

}  // namespace Botan
