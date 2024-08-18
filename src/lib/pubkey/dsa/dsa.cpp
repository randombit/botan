/*
* DSA
* (C) 1999-2010,2014,2016,2023 Jack Lloyd
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dsa.h>

#include <botan/numthry.h>
#include <botan/internal/divide.h>
#include <botan/internal/dl_scheme.h>
#include <botan/internal/keypair.h>
#include <botan/internal/pk_ops_impl.h>

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   #include <botan/internal/rfc6979.h>
#endif

namespace Botan {

size_t DSA_PublicKey::message_part_size() const {
   return m_public_key->group().q_bytes();
}

size_t DSA_PublicKey::estimated_strength() const {
   return m_public_key->estimated_strength();
}

size_t DSA_PublicKey::key_length() const {
   return m_public_key->p_bits();
}

const BigInt& DSA_PublicKey::get_int_field(std::string_view field) const {
   return m_public_key->get_int_field(algo_name(), field);
}

AlgorithmIdentifier DSA_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), m_public_key->group().DER_encode(DL_Group_Format::ANSI_X9_57));
}

std::vector<uint8_t> DSA_PublicKey::raw_public_key_bits() const {
   return m_public_key->public_key_as_bytes();
}

std::vector<uint8_t> DSA_PublicKey::public_key_bits() const {
   return m_public_key->DER_encode();
}

bool DSA_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_public_key->check_key(rng, strong);
}

std::unique_ptr<Private_Key> DSA_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<DSA_PrivateKey>(rng, m_public_key->group());
}

DSA_PublicKey::DSA_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_public_key = std::make_shared<DL_PublicKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_57);

   BOTAN_ARG_CHECK(m_public_key->group().has_q(), "Q parameter must be set for DSA");
}

DSA_PublicKey::DSA_PublicKey(const DL_Group& group, const BigInt& y) {
   m_public_key = std::make_shared<DL_PublicKey>(group, y);

   BOTAN_ARG_CHECK(m_public_key->group().has_q(), "Q parameter must be set for DSA");
}

DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group) {
   BOTAN_ARG_CHECK(group.has_q(), "Q parameter must be set for DSA");

   m_private_key = std::make_shared<DL_PrivateKey>(group, rng);
   m_public_key = m_private_key->public_key();
}

DSA_PrivateKey::DSA_PrivateKey(const DL_Group& group, const BigInt& x) {
   BOTAN_ARG_CHECK(group.has_q(), "Q parameter must be set for DSA");

   m_private_key = std::make_shared<DL_PrivateKey>(group, x);
   m_public_key = m_private_key->public_key();
}

DSA_PrivateKey::DSA_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_private_key = std::make_shared<DL_PrivateKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_57);
   m_public_key = m_private_key->public_key();

   BOTAN_ARG_CHECK(m_private_key->group().has_q(), "Q parameter must be set for DSA");
}

bool DSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!m_private_key->check_key(rng, strong)) {
      return false;
   }

   if(m_private_key->private_key() >= m_private_key->group().get_q()) {
      return false;
   }

   return KeyPair::signature_consistency_check(rng, *this, "SHA-256");
}

secure_vector<uint8_t> DSA_PrivateKey::private_key_bits() const {
   return m_private_key->DER_encode();
}

secure_vector<uint8_t> DSA_PrivateKey::raw_private_key_bits() const {
   return m_private_key->raw_private_key_bits();
}

const BigInt& DSA_PrivateKey::get_int_field(std::string_view field) const {
   return m_private_key->get_int_field(algo_name(), field);
}

std::unique_ptr<Public_Key> DSA_PrivateKey::public_key() const {
   // can't use make_unique here due to private constructor
   return std::unique_ptr<DSA_PublicKey>(new DSA_PublicKey(m_public_key));
}

namespace {

/**
* Object that can create a DSA signature
*/
class DSA_Signature_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      DSA_Signature_Operation(const std::shared_ptr<const DL_PrivateKey>& key,
                              const PK_Signature_Options& options,
                              RandomNumberGenerator& rng) :
            PK_Ops::Signature_with_Hash(options), m_key(key) {
         m_b = BigInt::random_integer(rng, 2, m_key->group().get_q());
         m_b_inv = m_key->group().inverse_mod_q(m_b);
      }

      size_t signature_length() const override { return 2 * m_key->group().q_bytes(); }

      std::vector<uint8_t> raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) override;

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      std::shared_ptr<const DL_PrivateKey> m_key;
      BigInt m_b, m_b_inv;
};

AlgorithmIdentifier DSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "DSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::vector<uint8_t> DSA_Signature_Operation::raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) {
   const DL_Group& group = m_key->group();
   const BigInt& q = group.get_q();

   BigInt m = BigInt::from_bytes_with_max_bits(msg.data(), msg.size(), group.q_bits());

   if(m >= q) {
      m -= q;
   }

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   BOTAN_UNUSED(rng);
   const BigInt k = generate_rfc6979_nonce(m_key->private_key(), q, m, this->rfc6979_hash_function());
#else
   const BigInt k = BigInt::random_integer(rng, 1, q);
#endif

   const BigInt k_inv = group.inverse_mod_q(k);

   /*
   * It may not be strictly necessary for the reduction (g^k mod p) mod q to be
   * const time, since r is published as part of the signature, and deriving
   * anything useful about k from g^k mod p would seem to require computing a
   * discrete logarithm.
   *
   * However it only increases the cost of signatures by about 7-10%, and DSA is
   * only for legacy use anyway so we don't care about the performance so much.
   */
   const BigInt r = ct_modulo(group.power_g_p(k, group.q_bits()), group.get_q());

   /*
   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
   */
   m_b = group.square_mod_q(m_b);
   m_b_inv = group.square_mod_q(m_b_inv);

   m = group.multiply_mod_q(m_b, m);
   const BigInt xr = group.multiply_mod_q(m_b, m_key->private_key(), r);

   const BigInt s = group.multiply_mod_q(m_b_inv, k_inv, group.mod_q(xr + m));

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero()) {
      throw Internal_Error("Computed zero r/s during DSA signature");
   }

   return unlock(BigInt::encode_fixed_length_int_pair(r, s, q.bytes()));
}

/**
* Object that can verify a DSA signature
*/
class DSA_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      DSA_Verification_Operation(const std::shared_ptr<const DL_PublicKey>& key, const PK_Signature_Options& options) :
            PK_Ops::Verification_with_Hash(options), m_key(key) {}

      DSA_Verification_Operation(const std::shared_ptr<const DL_PublicKey>& key, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(alg_id, "DSA"), m_key(key) {}

      bool verify(std::span<const uint8_t> input, std::span<const uint8_t> sig) override;

   private:
      std::shared_ptr<const DL_PublicKey> m_key;
};

bool DSA_Verification_Operation::verify(std::span<const uint8_t> input, std::span<const uint8_t> sig) {
   const auto group = m_key->group();

   const BigInt& q = group.get_q();
   const size_t q_bytes = q.bytes();

   if(sig.size() != 2 * q_bytes) {
      return false;
   }

   BigInt r(sig.first(q_bytes));
   BigInt s(sig.last(q_bytes));

   if(r == 0 || r >= q || s == 0 || s >= q) {
      return false;
   }

   BigInt i = BigInt::from_bytes_with_max_bits(input.data(), input.size(), group.q_bits());
   if(i >= q) {
      i -= q;
   }

   s = inverse_mod(s, q);

   const BigInt sr = group.multiply_mod_q(s, r);
   const BigInt si = group.multiply_mod_q(s, i);

   s = group.multi_exponentiate(si, m_key->public_key(), sr);

   // s is too big for Barrett, and verification doesn't need to be const-time
   return (s % group.get_q() == r);
}

}  // namespace

std::unique_ptr<PK_Ops::Verification> DSA_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   if(!options.using_provider()) {
      return std::make_unique<DSA_Verification_Operation>(this->m_public_key, options);
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

std::unique_ptr<PK_Ops::Verification> DSA_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<DSA_Verification_Operation>(this->m_public_key, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> DSA_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                        const PK_Signature_Options& options) const {
   if(!options.using_provider()) {
      return std::make_unique<DSA_Signature_Operation>(this->m_private_key, options, rng);
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

}  // namespace Botan
