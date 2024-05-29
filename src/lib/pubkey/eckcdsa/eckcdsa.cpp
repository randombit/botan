/*
* ECKCDSA (ISO/IEC 14888-3:2006/Cor.2:2009)
* (C) 2016 René Korthaus, Sirrix AG
* (C) 2018 Jack Lloyd
* (C) 2023 Philippe Lieser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eckcdsa.h>

#include <botan/hash.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keypair.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
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

std::vector<uint8_t> eckcdsa_prefix(const EC_Point& point, size_t hash_block_size) {
   auto prefix = concat<std::vector<uint8_t>>(point.x_bytes(), point.y_bytes());

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
void truncate_hash_if_needed(secure_vector<uint8_t>& digest, size_t group_order_bytes) {
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
      ECKCDSA_Signature_Operation(const ECKCDSA_PrivateKey& eckcdsa, std::string_view padding) :
            m_group(eckcdsa.domain()),
            m_x(eckcdsa.private_value()),
            m_hash(eckcdsa_signature_hash(padding)),
            m_prefix_used(false) {
         m_prefix = eckcdsa_prefix(eckcdsa.public_point(), m_hash->hash_block_size());
      }

      void update(const uint8_t msg[], size_t msg_len) override {
         if(!m_prefix_used) {
            m_hash->update(m_prefix.data(), m_prefix.size());
            m_prefix_used = true;
         }
         m_hash->update(msg, msg_len);
      }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         m_prefix_used = false;
         secure_vector<uint8_t> digest = m_hash->final();
         truncate_hash_if_needed(digest, m_group.get_order_bytes());
         return raw_sign(digest.data(), digest.size(), rng);
      }

      size_t signature_length() const override { return 2 * m_group.get_order_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_hash->name(); }

   private:
      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len, RandomNumberGenerator& rng);

      const EC_Group m_group;
      const BigInt m_x;
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

secure_vector<uint8_t> ECKCDSA_Signature_Operation::raw_sign(const uint8_t msg[],
                                                             size_t msg_len,
                                                             RandomNumberGenerator& rng) {
   const BigInt k = m_group.random_scalar(rng);
   const BigInt k_times_P_x = m_group.blinded_base_point_multiply_x(k, rng, m_ws);

   auto hash = m_hash->new_object();
   hash->update(k_times_P_x.serialize(m_group.get_order_bytes()));
   secure_vector<uint8_t> c = hash->final();
   truncate_hash_if_needed(c, m_group.get_order_bytes());

   const auto r = c;

   BOTAN_ASSERT_NOMSG(msg_len == c.size());
   xor_buf(c, msg, c.size());
   const BigInt w = m_group.mod_order(BigInt::from_bytes(c));

   const BigInt s = m_group.multiply_mod_order(m_x, k - w);
   if(s.is_zero()) {
      throw Internal_Error("During ECKCDSA signature generation created zero s");
   }

   return concat(r, s.serialize(m_group.get_order_bytes()));
}

/**
* ECKCDSA verification operation
*/
class ECKCDSA_Verification_Operation final : public PK_Ops::Verification {
   public:
      ECKCDSA_Verification_Operation(const ECKCDSA_PublicKey& eckcdsa, std::string_view padding) :
            m_group(eckcdsa.domain()),
            m_gy_mul(m_group.get_base_point(), eckcdsa.public_point()),
            m_hash(eckcdsa_signature_hash(padding)),
            m_prefix_used(false) {
         m_prefix = eckcdsa_prefix(eckcdsa.public_point(), m_hash->hash_block_size());
      }

      ECKCDSA_Verification_Operation(const ECKCDSA_PublicKey& eckcdsa, const AlgorithmIdentifier& alg_id) :
            m_group(eckcdsa.domain()),
            m_gy_mul(m_group.get_base_point(), eckcdsa.public_point()),
            m_hash(eckcdsa_signature_hash(alg_id)),
            m_prefix_used(false) {
         m_prefix = eckcdsa_prefix(eckcdsa.public_point(), m_hash->hash_block_size());
      }

      void update(const uint8_t msg[], size_t msg_len) override;

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;

      std::string hash_function() const override { return m_hash->name(); }

   private:
      bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len);

      const EC_Group m_group;
      const EC_Point_Multi_Point_Precompute m_gy_mul;
      std::vector<uint8_t> m_prefix;
      std::unique_ptr<HashFunction> m_hash;
      bool m_prefix_used;
};

void ECKCDSA_Verification_Operation::update(const uint8_t msg[], size_t msg_len) {
   if(!m_prefix_used) {
      m_prefix_used = true;
      m_hash->update(m_prefix.data(), m_prefix.size());
   }
   m_hash->update(msg, msg_len);
}

bool ECKCDSA_Verification_Operation::is_valid_signature(const uint8_t sig[], size_t sig_len) {
   m_prefix_used = false;
   secure_vector<uint8_t> digest = m_hash->final();
   truncate_hash_if_needed(digest, m_group.get_order_bytes());
   return verify(digest.data(), digest.size(), sig, sig_len);
}

bool ECKCDSA_Verification_Operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) {
   //calculate size of r

   const size_t order_bytes = m_group.get_order_bytes();

   const size_t size_r = std::min(msg_len, order_bytes);
   if(sig_len != size_r + order_bytes) {
      return false;
   }

   secure_vector<uint8_t> r(sig, sig + size_r);

   // check that 0 < s < q
   const BigInt s(sig + size_r, order_bytes);

   if(s <= 0 || s >= m_group.get_order()) {
      return false;
   }

   secure_vector<uint8_t> r_xor_e(r);
   xor_buf(r_xor_e, msg, r.size());

   const BigInt w = m_group.mod_order(BigInt::from_bytes(r_xor_e));

   const EC_Point q = m_gy_mul.multi_exp(w, s);
   if(q.is_zero()) {
      return false;
   }

   auto c_hash = m_hash->new_object();
   c_hash->update(q.x_bytes());
   secure_vector<uint8_t> v = c_hash->final();
   truncate_hash_if_needed(v, m_group.get_order_bytes());

   return (v == r);
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

std::unique_ptr<PK_Ops::Signature> ECKCDSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                           std::string_view params,
                                                                           std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ECKCDSA_Signature_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
