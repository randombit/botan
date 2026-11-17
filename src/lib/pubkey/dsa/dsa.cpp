/*
* DSA
* (C) 1999-2010,2014,2016,2023 Jack Lloyd
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dsa.h>

#include <botan/exceptn.h>
#include <botan/pk_options_readers.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/dl_scalar.h>
#include <botan/internal/dl_scheme.h>
#include <botan/internal/keypair.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pk_options_impl.h>

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   #include <botan/internal/rfc6979.h>
#endif

namespace Botan {

namespace {

void check_dsa_group(const DL_Group& group) {
   if(!group.has_q()) {
      throw Decoding_Error("Q parameter must be set for DSA");
   }

   const size_t q_bits = group.q_bits();
   const size_t p_bits = group.p_bits();

   // This accepts a superset of the valid p,q parameters that were ever
   // actually valid for DSA. Somewhat by accident, botan_privkey_create_dsa
   // skips using the DSA parameter generator (which has always enforced that p
   // and q are sized appropriately for FIPS 186) and instead allows generating
   // a wider range of key sizes.
   //
   // The size checks below are effectively a union of what is (or was) allowed
   // by FIPS 186, plus what botan_privkey_create_dsa will generate.
   //
   // TODO(Botan4) restrict to exactly the parameter sizes from FIPS 186-4
   // (1024,160), (2048,224), (2048,256), or (3072,256)

   if(q_bits < 160 || q_bits > 256 || (q_bits % 8) != 0) {
      throw Decoding_Error("Invalid DSA q parameter size");
   }
   if(p_bits < 512 || p_bits > 3072 || (p_bits % 64) != 0) {
      throw Decoding_Error("Invalid DSA p parameter size");
   }
}

}  // namespace

std::optional<size_t> DSA_PublicKey::_signature_element_size_for_DER_encoding() const {
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

   check_dsa_group(m_public_key->group());
}

DSA_PublicKey::DSA_PublicKey(const DL_Group& group, const BigInt& y) {
   m_public_key = std::make_shared<DL_PublicKey>(group, y);

   check_dsa_group(m_public_key->group());
}

DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group) {
   check_dsa_group(group);

   m_private_key = std::make_shared<DL_PrivateKey>(group, rng);
   m_public_key = m_private_key->public_key();
}

DSA_PrivateKey::DSA_PrivateKey(const DL_Group& group, const BigInt& x) {
   check_dsa_group(group);

   m_private_key = std::make_shared<DL_PrivateKey>(group, x);
   m_public_key = m_private_key->public_key();
}

DSA_PrivateKey::DSA_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_private_key = std::make_shared<DL_PrivateKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_57);
   m_public_key = m_private_key->public_key();

   check_dsa_group(m_private_key->group());
}

bool DSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!m_private_key->check_key(rng, strong)) {
      return false;
   }

   if(!strong) {
      return true;
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
                              const PK_Signature_Options_Reader& options,
                              RandomNumberGenerator& rng) :
            PK_Ops::Signature_with_Hash(options),
            m_key(key),
            m_x(DL_Scalar::from_bigint(m_key->group(), m_key->private_key())),
            m_b(DL_Scalar::random(m_key->group(), rng)),
            m_b_inv(m_b.invert()),
            m_deterministic(options.using_deterministic_signature()) {
#if !defined(BOTAN_HAS_RFC6979_GENERATOR)
         if(m_deterministic) {
            throw Not_Implemented("Deterministic DSA signatures require RFC 6979 support");
         }
#endif
      }

      size_t signature_length() const override { return 2 * m_key->group().q_bytes(); }

      std::vector<uint8_t> raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) override;

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      std::shared_ptr<const DL_PrivateKey> m_key;
      DL_Scalar m_x;
      DL_Scalar m_b;
      DL_Scalar m_b_inv;
      bool m_deterministic;
};

AlgorithmIdentifier DSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "DSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::vector<uint8_t> DSA_Signature_Operation::raw_sign(std::span<const uint8_t> msg, RandomNumberGenerator& rng) {
   const DL_Group& group = m_key->group();

   const auto m = DL_Scalar::from_bytes_with_trunc(group, msg);

   const auto scope = CT::scoped_poison(m_key->private_key(), m_x, m_b, m_b_inv);

   const auto k = [&]() {
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
      if(m_deterministic) {
         return DL_Scalar::from_bigint(
            group,
            generate_rfc6979_nonce(m_key->private_key(), group.get_q(), m.to_bigint(), this->rfc6979_hash_function()));
      }
#endif
      return DL_Scalar::random(group, rng);
   }();
   CT::poison(k);

   const auto k_inv = (m_b * k).invert() * m_b;

   const auto r = DL_Scalar::g_pow_mod_q(k);

   /*
   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
   */
   m_b = m_b.square();
   m_b_inv = m_b_inv.square();

   const auto mb = m_b * m;
   const auto xrb = m_b * m_x * r;

   const auto s = m_b_inv * k_inv * (xrb + mb);

   CT::unpoison_all(r, s);

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero()) {
      throw Internal_Error("Computed zero r/s during DSA signature");
   }

   const size_t q_bytes = group.q_bytes();
   std::vector<uint8_t> sig(2 * q_bytes);
   BufferStuffer stuffer(sig);
   r.serialize_to(stuffer.next(q_bytes));
   s.serialize_to(stuffer.next(q_bytes));
   return sig;
}

/**
* Object that can verify a DSA signature
*/
class DSA_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      DSA_Verification_Operation(const std::shared_ptr<const DL_PublicKey>& key,
                                 const PK_Signature_Options_Reader& options) :
            PK_Ops::Verification_with_Hash(options), m_key(key) {}

      DSA_Verification_Operation(const std::shared_ptr<const DL_PublicKey>& key, const AlgorithmIdentifier& alg_id) :
            PK_Ops::Verification_with_Hash(alg_id, "DSA"), m_key(key) {}

      bool verify(std::span<const uint8_t> input, std::span<const uint8_t> sig) override;

   private:
      std::shared_ptr<const DL_PublicKey> m_key;
};

bool DSA_Verification_Operation::verify(std::span<const uint8_t> input, std::span<const uint8_t> sig) {
   const DL_Group& group = m_key->group();

   const size_t q_bytes = group.q_bytes();

   if(sig.size() != 2 * q_bytes) {
      return false;
   }

   const auto r = DL_Scalar::deserialize(group, sig.first(q_bytes));
   const auto s = DL_Scalar::deserialize(group, sig.last(q_bytes));

   if(!r || !s || r->is_zero() || s->is_zero()) {
      return false;
   }

   const auto i = DL_Scalar::from_bytes_with_trunc(group, input);

   const auto w = s->invert();

   const auto v = DL_Scalar::multi_exp_mod_q_vartime(w * i, m_key->public_key(), w * (*r));

   return (v == *r);
}

}  // namespace

std::unique_ptr<PK_Ops::Verification> DSA_PublicKey::_create_verification_op(
   const PK_Signature_Options_Reader& options) const {
   require_software_provider(options, algo_name());

   return std::make_unique<DSA_Verification_Operation>(this->m_public_key, options);
}

std::unique_ptr<PK_Ops::Verification> DSA_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<DSA_Verification_Operation>(this->m_public_key, signature_algorithm);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> DSA_PrivateKey::_create_signature_op(
   RandomNumberGenerator& rng, const PK_Signature_Options_Reader& options) const {
   require_software_provider(options, algo_name());

   return std::make_unique<DSA_Signature_Operation>(this->m_private_key, options, rng);
}

}  // namespace Botan
