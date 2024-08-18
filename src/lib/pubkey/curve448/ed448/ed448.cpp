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
#include <botan/internal/pk_options_impl.h>

#include <utility>

namespace Botan {

AlgorithmIdentifier Ed448_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool Ed448_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   try {
      Ed448Point::decode(m_public);
   } catch(Decoding_Error&) {
      return false;
   }
   return true;
}

Ed448_PublicKey::Ed448_PublicKey(const AlgorithmIdentifier& /* unused */, std::span<const uint8_t> key_bits) :
      Ed448_PublicKey(key_bits) {}

Ed448_PublicKey::Ed448_PublicKey(std::span<const uint8_t> key_bits) {
   if(key_bits.size() != ED448_LEN) {
      throw Decoding_Error("Invalid length for Ed448 public key");
   }
   copy_mem(m_public, key_bits.first<ED448_LEN>());
}

std::vector<uint8_t> Ed448_PublicKey::raw_public_key_bits() const {
   return {m_public.begin(), m_public.end()};
}

std::vector<uint8_t> Ed448_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> Ed448_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Ed448_PrivateKey>(rng);
}

Ed448_PrivateKey::Ed448_PrivateKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) {
   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits).decode(bits, ASN1_Type::OctetString).verify_end();

   if(bits.size() != ED448_LEN) {
      throw Decoding_Error("Invalid size for Ed448 private key");
   }
   m_private = std::move(bits);
   m_public = create_pk_from_sk(std::span(m_private).first<ED448_LEN>());
}

Ed448_PrivateKey::Ed448_PrivateKey(RandomNumberGenerator& rng) : Ed448_PrivateKey(rng.random_vec(ED448_LEN)) {}

Ed448_PrivateKey::Ed448_PrivateKey(std::span<const uint8_t> key_bits) {
   if(key_bits.size() != ED448_LEN) {
      throw Decoding_Error("Invalid size for Ed448 private key");
   }
   m_private.assign(key_bits.begin(), key_bits.end());
   auto scope = CT::scoped_poison(m_private);
   m_public = create_pk_from_sk(std::span(m_private).first<ED448_LEN>());
   CT::unpoison(m_public);
}

std::unique_ptr<Public_Key> Ed448_PrivateKey::public_key() const {
   return std::make_unique<Ed448_PublicKey>(m_public);
}

secure_vector<uint8_t> Ed448_PrivateKey::private_key_bits() const {
   BOTAN_ASSERT_NOMSG(m_private.size() == ED448_LEN);
   return DER_Encoder().encode(m_private, ASN1_Type::OctetString).get_contents();
}

bool Ed448_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   return true;
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

      Prehashed_Ed448_Message(std::string_view hash) : m_hash(HashFunction::create_or_throw(hash)) {}

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
      explicit Ed448_Verify_Operation(const Ed448_PublicKey& key,
                                      std::optional<std::string> prehash_function = std::nullopt) :
            m_prehash_function(std::move(prehash_function)) {
         const auto pk_bits = key.public_key_bits();
         copy_mem(m_pk, std::span(pk_bits).first<ED448_LEN>());
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
            return verify_signature(m_pk, m_prehash_function.has_value(), {}, sig, msg);
         } catch(Decoding_Error&) {
            return false;
         }
      }

      std::string hash_function() const override { return m_prehash_function.value_or("SHAKE-256(912)"); }

   private:
      std::array<uint8_t, ED448_LEN> m_pk;
      std::unique_ptr<Ed448_Message> m_message;
      std::optional<std::string> m_prehash_function;
};

/**
* Ed448 signing operation
*/
class Ed448_Sign_Operation final : public PK_Ops::Signature {
   public:
      explicit Ed448_Sign_Operation(const Ed448_PrivateKey& key,
                                    std::optional<std::string> prehash_function = std::nullopt) :
            m_prehash_function(std::move(prehash_function)) {
         const auto pk_bits = key.public_key_bits();
         copy_mem(m_pk, std::span(pk_bits).first<ED448_LEN>());
         const auto sk_bits = key.raw_private_key_bits();
         BOTAN_ASSERT_NOMSG(sk_bits.size() == ED448_LEN);
         m_sk.assign(sk_bits.begin(), sk_bits.end());
         if(m_prehash_function) {
            m_message = std::make_unique<Prehashed_Ed448_Message>(*m_prehash_function);
         } else {
            m_message = std::make_unique<Pure_Ed448_Message>();
         }
      }

      void update(std::span<const uint8_t> input) override { m_message->update(input); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         BOTAN_ASSERT_NOMSG(m_sk.size() == ED448_LEN);
         auto scope = CT::scoped_poison(m_sk);
         const auto sig = sign_message(
            std::span(m_sk).first<ED448_LEN>(), m_pk, m_prehash_function.has_value(), {}, m_message->get_and_clear());
         CT::unpoison(sig);
         return {sig.begin(), sig.end()};
      }

      size_t signature_length() const override { return 2 * ED448_LEN; }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_prehash_function.value_or("SHAKE-256(912)"); }

   private:
      std::array<uint8_t, ED448_LEN> m_pk;
      secure_vector<uint8_t> m_sk;
      std::unique_ptr<Ed448_Message> m_message;
      std::optional<std::string> m_prehash_function;
};

AlgorithmIdentifier Ed448_Sign_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("Ed448"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

}  // namespace

std::unique_ptr<PK_Ops::Verification> Ed448_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   BOTAN_ARG_CHECK(!options.using_padding(), "Ed448 does not support padding");

   if(!options.using_provider()) {
      if(options.using_prehash()) {
         // TODO(C++23) options.prehash_fn().or_else("SHAKE-256(512)")
         const auto prehash_fn = options.prehash_fn().has_value() ? options.prehash_fn().value() : "SHAKE-256(512)";
         return std::make_unique<Ed448_Verify_Operation>(*this, prehash_fn);
      } else {
         return std::make_unique<Ed448_Verify_Operation>(*this);
      }
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
}

std::unique_ptr<PK_Ops::Verification> Ed448_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                   std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Ed448 X509 signature");
      }

      return std::make_unique<Ed448_Verify_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> Ed448_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                          const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   BOTAN_ARG_CHECK(!options.using_padding(), "Ed448 does not support padding");

   if(!options.using_provider()) {
      if(options.using_prehash()) {
         // TODO(C++23) options.prehash_fn().or_else("SHAKE-256(512)")
         const auto prehash_fn = options.prehash_fn().has_value() ? options.prehash_fn().value() : "SHAKE-256(512)";
         return std::make_unique<Ed448_Sign_Operation>(*this, prehash_fn);
      } else {
         return std::make_unique<Ed448_Sign_Operation>(*this);
      }
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

}  // namespace Botan
