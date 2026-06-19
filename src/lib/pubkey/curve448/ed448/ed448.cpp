/*
 * Ed448 Signature Algorithm (RFC 8032)
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/ed448.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ed448_internal.h>
#include <botan/internal/pk_ops_impl.h>

#include <utility>

namespace Botan {

class Ed448_PublicKey_Data final {
   public:
      explicit Ed448_PublicKey_Data(std::array<uint8_t, ED448_LEN> key) : m_key(key) {}

      const std::array<uint8_t, ED448_LEN>& key() const { return m_key; }

   private:
      std::array<uint8_t, ED448_LEN> m_key;
};

class Ed448_PrivateKey_Data final {
   public:
      explicit Ed448_PrivateKey_Data(secure_vector<uint8_t> key) : m_key(std::move(key)) {}

      const secure_vector<uint8_t>& key() const { return m_key; }

   private:
      secure_vector<uint8_t> m_key;
};

secure_vector<uint8_t> Ed448_PrivateKey::raw_private_key_bits() const {
   const auto& sk = m_private->key();
   return {sk.begin(), sk.end()};
}

AlgorithmIdentifier Ed448_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool Ed448_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   try {
      Ed448Point::decode(m_public->key());
   } catch(Decoding_Error&) {
      return false;
   }
   return true;
}

Ed448_PublicKey::Ed448_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      Ed448_PublicKey(key_bits) {
   // RFC 8410 Section 3: "the parameters MUST be absent".
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for Ed448 public key");
   }
}

Ed448_PublicKey::Ed448_PublicKey(std::span<const uint8_t> key_bits) {
   if(key_bits.size() != ED448_LEN) {
      throw Decoding_Error("Invalid length for Ed448 public key");
   }
   std::array<uint8_t, ED448_LEN> pub{};
   copy_mem(pub, key_bits.first<ED448_LEN>());
   m_public = std::make_shared<const Ed448_PublicKey_Data>(pub);
}

std::vector<uint8_t> Ed448_PublicKey::raw_public_key_bits() const {
   const auto& pub = m_public->key();
   return {pub.begin(), pub.end()};
}

std::vector<uint8_t> Ed448_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> Ed448_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Ed448_PrivateKey>(rng);
}

Ed448_PrivateKey::Ed448_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // RFC 8410 Section 3: "the parameters MUST be absent".
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for Ed448 private key");
   }

   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits, BER_Decoder::Limits::DER()).decode(bits, ASN1_Type::OctetString).verify_end();

   if(bits.size() != ED448_LEN) {
      throw Decoding_Error("Invalid size for Ed448 private key");
   }
   auto pub = create_pk_from_sk(std::span(bits).first<ED448_LEN>());
   m_public = std::make_shared<const Ed448_PublicKey_Data>(pub);
   m_private = std::make_shared<const Ed448_PrivateKey_Data>(std::move(bits));
}

Ed448_PrivateKey::Ed448_PrivateKey(RandomNumberGenerator& rng) : Ed448_PrivateKey(rng.random_vec(ED448_LEN)) {}

Ed448_PrivateKey::Ed448_PrivateKey(std::span<const uint8_t> key_bits) {
   if(key_bits.size() != ED448_LEN) {
      throw Decoding_Error("Invalid size for Ed448 private key");
   }
   secure_vector<uint8_t> sk(key_bits.begin(), key_bits.end());
   std::array<uint8_t, ED448_LEN> pub{};
   {
      auto scope = CT::scoped_poison(sk);
      pub = create_pk_from_sk(std::span(sk).first<ED448_LEN>());
      CT::unpoison(pub);
   }
   m_public = std::make_shared<const Ed448_PublicKey_Data>(pub);
   m_private = std::make_shared<const Ed448_PrivateKey_Data>(std::move(sk));
}

std::unique_ptr<Public_Key> Ed448_PrivateKey::public_key() const {
   return std::make_unique<Ed448_PublicKey>(raw_public_key_bits());
}

secure_vector<uint8_t> Ed448_PrivateKey::private_key_bits() const {
   const auto& sk = m_private->key();
   BOTAN_ASSERT_NOMSG(sk.size() == ED448_LEN);
   return DER_Encoder().encode(sk, ASN1_Type::OctetString).get_contents();
}

bool Ed448_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   const auto& sk = m_private->key();
   BOTAN_ASSERT_NOMSG(sk.size() == ED448_LEN);
   auto scope = CT::scoped_poison(sk);
   const auto public_point = create_pk_from_sk(std::span(sk).first<ED448_LEN>());
   CT::unpoison(public_point);
   return public_point == m_public->key();
}

namespace {

/// Interface to abstract either a pure message or a prehashed message
class Ed448_Message {
   public:
      virtual void update(std::span<const uint8_t> msg) = 0;
      virtual std::vector<uint8_t> get_and_clear() = 0;

      Ed448_Message() = default;
      virtual ~Ed448_Message() = default;
      Ed448_Message(const Ed448_Message&) = delete;
      Ed448_Message& operator=(const Ed448_Message&) = delete;
      Ed448_Message(Ed448_Message&&) = delete;
      Ed448_Message& operator=(Ed448_Message&&) = delete;
};

class Prehashed_Ed448_Message final : public Ed448_Message {
   public:
      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      std::vector<uint8_t> get_and_clear() override { return m_hash->final_stdvec(); }

      explicit Prehashed_Ed448_Message(std::string_view hash) : m_hash(HashFunction::create_or_throw(hash)) {}

   private:
      std::unique_ptr<HashFunction> m_hash;
};

class Pure_Ed448_Message final : public Ed448_Message {
   public:
      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      std::vector<uint8_t> get_and_clear() override { return std::exchange(m_msg, {}); }

   private:
      std::vector<uint8_t> m_msg;
};

/**
* Ed448 verifying operation
*/
class Ed448_Verify_Operation final : public PK_Ops::Verification {
   public:
      explicit Ed448_Verify_Operation(std::shared_ptr<const Ed448_PublicKey_Data> public_key,
                                      std::optional<std::string> prehash_function = std::nullopt) :
            m_public_key(std::move(public_key)), m_prehash_function(std::move(prehash_function)) {
         if(m_prehash_function) {
            m_message = std::make_unique<Prehashed_Ed448_Message>(*m_prehash_function);
         } else {
            m_message = std::make_unique<Pure_Ed448_Message>();
         }
      }

      void update(std::span<const uint8_t> input) override { m_message->update(input); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         const auto msg = m_message->get_and_clear();
         try {
            return verify_signature(
               std::span(m_public_key->key()).first<ED448_LEN>(), m_prehash_function.has_value(), {}, sig, msg);
         } catch(Decoding_Error&) {
            return false;
         }
      }

      std::string hash_function() const override { return m_prehash_function.value_or("SHAKE-256(912)"); }

   private:
      std::shared_ptr<const Ed448_PublicKey_Data> m_public_key;
      std::unique_ptr<Ed448_Message> m_message;
      std::optional<std::string> m_prehash_function;
};

/**
* Ed448 signing operation
*/
class Ed448_Sign_Operation final : public PK_Ops::Signature {
   public:
      Ed448_Sign_Operation(std::shared_ptr<const Ed448_PublicKey_Data> public_key,
                           std::shared_ptr<const Ed448_PrivateKey_Data> private_key,
                           std::optional<std::string> prehash_function = std::nullopt) :
            m_public_key(std::move(public_key)),
            m_private_key(std::move(private_key)),
            m_prehash_function(std::move(prehash_function)) {
         if(m_prehash_function) {
            m_message = std::make_unique<Prehashed_Ed448_Message>(*m_prehash_function);
         } else {
            m_message = std::make_unique<Pure_Ed448_Message>();
         }
      }

      void update(std::span<const uint8_t> input) override { m_message->update(input); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         const auto& sk = m_private_key->key();
         BOTAN_ASSERT_NOMSG(sk.size() == ED448_LEN);
         auto scope = CT::scoped_poison(sk);
         const auto sig = sign_message(std::span(sk).first<ED448_LEN>(),
                                       std::span(m_public_key->key()).first<ED448_LEN>(),
                                       m_prehash_function.has_value(),
                                       {},
                                       m_message->get_and_clear());
         CT::unpoison(sig);
         return {sig.begin(), sig.end()};
      }

      size_t signature_length() const override { return 2 * ED448_LEN; }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_prehash_function.value_or("SHAKE-256(912)"); }

   private:
      std::shared_ptr<const Ed448_PublicKey_Data> m_public_key;
      std::shared_ptr<const Ed448_PrivateKey_Data> m_private_key;
      std::unique_ptr<Ed448_Message> m_message;
      std::optional<std::string> m_prehash_function;
};

AlgorithmIdentifier Ed448_Sign_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("Ed448"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

}  // namespace

std::unique_ptr<PK_Ops::Verification> Ed448_PublicKey::create_verification_op(std::string_view params,
                                                                              std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(params.empty() || params == "Identity" || params == "Pure" || params == "Ed448") {
         return std::make_unique<Ed448_Verify_Operation>(m_public);
      } else if(params == "Ed448ph") {
         return std::make_unique<Ed448_Verify_Operation>(m_public, "SHAKE-256(512)");
      } else {
         return std::make_unique<Ed448_Verify_Operation>(m_public, std::string(params));
      }
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> Ed448_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                   std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(alg_id.oid() != this->object_identifier() || !alg_id.parameters_are_empty()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Ed448 X509 signature");
      }

      return std::make_unique<Ed448_Verify_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> Ed448_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                         std::string_view params,
                                                                         std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(params.empty() || params == "Identity" || params == "Pure" || params == "Ed448") {
         return std::make_unique<Ed448_Sign_Operation>(m_public, m_private);
      } else if(params == "Ed448ph") {
         return std::make_unique<Ed448_Sign_Operation>(m_public, m_private, "SHAKE-256(512)");
      } else {
         return std::make_unique<Ed448_Sign_Operation>(m_public, m_private, std::string(params));
      }
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
