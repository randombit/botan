/**
* HSS-LMS
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hss_lms.h>

#include <botan/rng.h>
#include <botan/internal/hss.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

HSS_LMS_PublicKey::HSS_LMS_PublicKey(std::span<const uint8_t> pub_key) :
      m_public(HSS_LMS_PublicKeyInternal::from_bytes_or_throw(pub_key)) {}

HSS_LMS_PublicKey::~HSS_LMS_PublicKey() = default;

size_t HSS_LMS_PublicKey::key_length() const {
   return m_public->size();
}

size_t HSS_LMS_PublicKey::estimated_strength() const {
   // draft-fluhrer-lms-more-parm-sets-11 Section 9.
   //   As shown in [Katz16], if we assume that the hash function can be
   //   modeled as a random oracle, then the security of the system is at
   //   least 8N-1 bits (where N is the size of the hash output in bytes);
   return 8 * m_public->lms_pub_key().lms_params().m() - 1;
}

std::string HSS_LMS_PublicKey::algo_name() const {
   return m_public->algo_name();
}

AlgorithmIdentifier HSS_LMS_PublicKey::algorithm_identifier() const {
   return m_public->algorithm_identifier();
}

OID HSS_LMS_PublicKey::object_identifier() const {
   return m_public->object_identifier();
}

bool HSS_LMS_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   // Nothing to check. Only useful checks are already done during parsing.
   return true;
}

std::vector<uint8_t> HSS_LMS_PublicKey::raw_public_key_bits() const {
   return m_public->to_bytes();
}

std::vector<uint8_t> HSS_LMS_PublicKey::public_key_bits() const {
   // The raw encoding of HSS/LMS public keys always contains the necessary
   // algorithm information.
   return raw_public_key_bits();
}

class HSS_LMS_Verification_Operation final : public PK_Ops::Verification {
   public:
      HSS_LMS_Verification_Operation(std::shared_ptr<HSS_LMS_PublicKeyInternal> pub_key) :
            m_public(std::move(pub_key)) {}

      void update(std::span<const uint8_t> msg) override {
         m_msg_buffer.insert(m_msg_buffer.end(), msg.begin(), msg.end());
      }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         std::vector<uint8_t> message_to_verify = std::exchange(m_msg_buffer, {});
         try {
            const auto signature = HSS_Signature::from_bytes_or_throw(sig);
            return m_public->verify_signature(message_to_verify, signature);
         } catch(const Decoding_Error&) {
            // Signature could not be decoded
            return false;
         }
      }

      std::string hash_function() const override { return m_public->lms_pub_key().lms_params().hash_name(); }

   private:
      std::shared_ptr<HSS_LMS_PublicKeyInternal> m_public;
      std::vector<uint8_t> m_msg_buffer;
};

std::unique_ptr<PK_Ops::Verification> HSS_LMS_PublicKey::_create_verification_op(PK_Signature_Options& options) const {
   options.exclude_provider();
   options.validate_for_hash_based_signature();
   return std::make_unique<HSS_LMS_Verification_Operation>(m_public);
}

std::unique_ptr<PK_Ops::Verification> HSS_LMS_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(signature_algorithm != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for HSS-LMS signature");
      }
      return std::make_unique<HSS_LMS_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

bool HSS_LMS_PublicKey::supports_operation(PublicKeyOperation op) const {
   return op == PublicKeyOperation::Signature;
}

std::unique_ptr<Private_Key> HSS_LMS_PublicKey::generate_another(RandomNumberGenerator&) const {
   // For this key type we cannot derive all required parameters from just
   // the public key. It is however possible to call HSS_LMS_PrivateKey::generate_another().
   throw Not_Implemented("Cannot generate a new HSS/LMS keypair from a public key");
}

HSS_LMS_PrivateKey::HSS_LMS_PrivateKey(std::span<const uint8_t> private_key) {
   m_private = HSS_LMS_PrivateKeyInternal::from_bytes_or_throw(private_key);
   auto scope = CT::scoped_poison(*m_private);
   m_public = std::make_shared<HSS_LMS_PublicKeyInternal>(HSS_LMS_PublicKeyInternal::create(*m_private));
   CT::unpoison(*m_public);
}

HSS_LMS_PrivateKey::HSS_LMS_PrivateKey(RandomNumberGenerator& rng, std::string_view algo_params) {
   HSS_LMS_Params hss_params(algo_params);
   m_private = std::make_shared<HSS_LMS_PrivateKeyInternal>(hss_params, rng);
   auto scope = CT::scoped_poison(*m_private);
   m_public = std::make_shared<HSS_LMS_PublicKeyInternal>(HSS_LMS_PublicKeyInternal::create(*m_private));
   CT::unpoison(*m_public);
}

HSS_LMS_PrivateKey::HSS_LMS_PrivateKey(std::shared_ptr<HSS_LMS_PrivateKeyInternal> sk) : m_private(std::move(sk)) {
   auto scope = CT::scoped_poison(*m_private);
   m_public = std::make_shared<HSS_LMS_PublicKeyInternal>(HSS_LMS_PublicKeyInternal::create(*m_private));
   CT::unpoison(*m_public);
}

HSS_LMS_PrivateKey::~HSS_LMS_PrivateKey() = default;

secure_vector<uint8_t> HSS_LMS_PrivateKey::private_key_bits() const {
   auto scope = CT::scoped_poison(*m_private);
   return CT::driveby_unpoison(m_private->to_bytes());
}

secure_vector<uint8_t> HSS_LMS_PrivateKey::raw_private_key_bits() const {
   return private_key_bits();
}

std::unique_ptr<Public_Key> HSS_LMS_PrivateKey::public_key() const {
   return std::make_unique<HSS_LMS_PublicKey>(*this);
}

// We use a separate algorithm identifier for the private key since we use a Botan scoped OID for it.
// This is necessary since the private key format is implementation specific, since it is not defined
// in RFC 8554.
AlgorithmIdentifier HSS_LMS_PrivateKey::pkcs8_algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("HSS-LMS-Private-Key"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::optional<uint64_t> HSS_LMS_PrivateKey::remaining_operations() const {
   return (m_private->hss_params().max_sig_count() - m_private->get_idx()).get();
}

std::unique_ptr<Private_Key> HSS_LMS_PrivateKey::generate_another(RandomNumberGenerator& rng) const {
   // Cannot use std::make_unique because the utilized constructor is private.
   return std::unique_ptr<HSS_LMS_PrivateKey>(
      new HSS_LMS_PrivateKey(std::make_shared<HSS_LMS_PrivateKeyInternal>(m_private->hss_params(), rng)));
}

class HSS_LMS_Signature_Operation final : public PK_Ops::Signature {
   public:
      HSS_LMS_Signature_Operation(std::shared_ptr<HSS_LMS_PrivateKeyInternal> private_key,
                                  std::shared_ptr<HSS_LMS_PublicKeyInternal> public_key) :
            m_private(std::move(private_key)), m_public(std::move(public_key)) {}

      void update(std::span<const uint8_t> msg) override {
         m_msg_buffer.insert(m_msg_buffer.end(), msg.begin(), msg.end());
      }

      std::vector<uint8_t> sign(RandomNumberGenerator&) override {
         std::vector<uint8_t> message_to_sign = std::exchange(m_msg_buffer, {});
         auto scope = CT::scoped_poison(*m_private);
         return CT::driveby_unpoison(m_private->sign(message_to_sign));
      }

      size_t signature_length() const override { return m_private->signature_size(); }

      AlgorithmIdentifier algorithm_identifier() const override { return m_public->algorithm_identifier(); }

      std::string hash_function() const override { return m_public->lms_pub_key().lms_params().hash_name(); }

   private:
      std::shared_ptr<HSS_LMS_PrivateKeyInternal> m_private;
      std::shared_ptr<HSS_LMS_PublicKeyInternal> m_public;
      std::vector<uint8_t> m_msg_buffer;
};

std::unique_ptr<PK_Ops::Signature> HSS_LMS_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                            PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   options.exclude_provider();
   options.validate_for_hash_based_signature();

   return std::make_unique<HSS_LMS_Signature_Operation>(m_private, m_public);
}

}  // namespace Botan
