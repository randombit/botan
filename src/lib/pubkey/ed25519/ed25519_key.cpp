/*
* Ed25519
* (C) 2017 Ribose Inc
*     2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ed25519.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ed25519_internal.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

class Ed25519_PublicKey_Data final {
   public:
      explicit Ed25519_PublicKey_Data(std::vector<uint8_t> key) : m_key(std::move(key)) {}

      const std::vector<uint8_t>& key() const { return m_key; }

   private:
      std::vector<uint8_t> m_key;
};

class Ed25519_PrivateKey_Data final {
   public:
      explicit Ed25519_PrivateKey_Data(secure_vector<uint8_t> key) : m_key(std::move(key)) {}

      const secure_vector<uint8_t>& key() const { return m_key; }

   private:
      secure_vector<uint8_t> m_key;
};

const std::vector<uint8_t>& Ed25519_PublicKey::get_public_key() const {
   return m_public->key();
}

const secure_vector<uint8_t>& Ed25519_PrivateKey::get_private_key() const {
   return m_private->key();
}

secure_vector<uint8_t> Ed25519_PrivateKey::raw_private_key_bits() const {
   return m_private->key();
}

AlgorithmIdentifier Ed25519_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool Ed25519_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   const std::vector<uint8_t>& pub = m_public->key();

   if(pub.size() != 32) {
      return false;
   }

   /*
   This function was derived from public domain code in Tor's blinding.c
   */

   const uint8_t identity_element[32] = {1};
   if(CT::is_equal(pub.data(), identity_element, 32).as_bool()) {
      return false;
   }

   // Also reject the non-canonical encoding of the identity (y = 1 with the
   // sign bit set). The subgroup check below flips the sign bit before decoding,
   // which would otherwise normalize {0x01, .., 0x80} to the canonical identity
   // and let it pass.
   uint8_t noncanonical_identity[32] = {1};
   noncanonical_identity[31] = 0x80;
   if(CT::is_equal(pub.data(), noncanonical_identity, 32).as_bool()) {
      return false;
   }

   // The order of the Ed25519 group encoded
   const uint8_t modm_m[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                               0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

   const unsigned char zero[32] = {0};

   unsigned char pkcopy[32];

   copy_mem(pkcopy, pub.data(), 32);
   pkcopy[31] ^= (1 << 7);  // flip sign

   return signature_check(pkcopy, modm_m, identity_element, zero);
}

Ed25519_PublicKey::Ed25519_PublicKey(const uint8_t pub_key[], size_t pub_len) {
   if(pub_len != 32) {
      throw Decoding_Error("Invalid length for Ed25519 key");
   }
   m_public = std::make_shared<const Ed25519_PublicKey_Data>(std::vector<uint8_t>(pub_key, pub_key + pub_len));
}

Ed25519_PublicKey::Ed25519_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // RFC 8410 Section 3: "the parameters MUST be absent".
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for Ed25519 public key");
   }

   if(key_bits.size() != 32) {
      throw Decoding_Error("Invalid size for Ed25519 public key");
   }

   m_public = std::make_shared<const Ed25519_PublicKey_Data>(std::vector<uint8_t>(key_bits.begin(), key_bits.end()));
}

std::vector<uint8_t> Ed25519_PublicKey::raw_public_key_bits() const {
   return m_public->key();
}

std::vector<uint8_t> Ed25519_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> Ed25519_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Ed25519_PrivateKey>(rng);
}

namespace {

// Given the 64-byte expanded private key (32-byte private seed followed by the
// 32-byte public key) build the immutable public and private key data objects.
void load_ed25519_keypair(secure_vector<uint8_t> expanded_key,
                          std::shared_ptr<const Ed25519_PublicKey_Data>& pk_out,
                          std::shared_ptr<const Ed25519_PrivateKey_Data>& sk_out) {
   BOTAN_ASSERT_NOMSG(expanded_key.size() == 64);
   pk_out = std::make_shared<const Ed25519_PublicKey_Data>(
      std::vector<uint8_t>(expanded_key.begin() + 32, expanded_key.end()));
   sk_out = std::make_shared<const Ed25519_PrivateKey_Data>(std::move(expanded_key));
}

// Generate the 64-byte expanded private key from a 32-byte seed.
secure_vector<uint8_t> ed25519_expand_seed(std::span<const uint8_t> seed) {
   BOTAN_ASSERT_NOMSG(seed.size() == 32);
   std::vector<uint8_t> pk(32);  // also written into the expanded private key
   secure_vector<uint8_t> sk(64);
   ed25519_gen_keypair(pk.data(), sk.data(), seed.data());
   return sk;
}

}  // namespace

Ed25519_PrivateKey::Ed25519_PrivateKey(std::span<const uint8_t> secret_key) {
   if(secret_key.size() == 64) {
      load_ed25519_keypair(secure_vector<uint8_t>(secret_key.begin(), secret_key.end()), m_public, m_private);
   } else if(secret_key.size() == 32) {
      load_ed25519_keypair(ed25519_expand_seed(secret_key), m_public, m_private);
   } else {
      throw Decoding_Error("Invalid size for Ed25519 private key");
   }
}

//static
Ed25519_PrivateKey Ed25519_PrivateKey::from_seed(std::span<const uint8_t> seed) {
   BOTAN_ARG_CHECK(seed.size() == 32, "Ed25519 seed must be exactly 32 bytes long");
   return Ed25519_PrivateKey(seed);
}

//static
Ed25519_PrivateKey Ed25519_PrivateKey::from_bytes(std::span<const uint8_t> bytes) {
   BOTAN_ARG_CHECK(bytes.size() == 64, "Ed25519 private key must be exactly 64 bytes long");
   return Ed25519_PrivateKey(bytes);
}

Ed25519_PrivateKey::Ed25519_PrivateKey(RandomNumberGenerator& rng) {
   const secure_vector<uint8_t> seed = rng.random_vec(32);
   load_ed25519_keypair(ed25519_expand_seed(seed), m_public, m_private);
}

Ed25519_PrivateKey::Ed25519_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   // RFC 8410 Section 3: "the parameters MUST be absent".
   if(!alg_id.parameters_are_empty()) {
      throw Decoding_Error("Unexpected parameters for Ed25519 private key");
   }

   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits, BER_Decoder::Limits::DER()).decode(bits, ASN1_Type::OctetString).discard_remaining();

   if(bits.size() != 32) {
      throw Decoding_Error("Invalid size for Ed25519 private key");
   }
   load_ed25519_keypair(ed25519_expand_seed(bits), m_public, m_private);
}

std::unique_ptr<Public_Key> Ed25519_PrivateKey::public_key() const {
   return std::make_unique<Ed25519_PublicKey>(raw_public_key_bits());
}

secure_vector<uint8_t> Ed25519_PrivateKey::private_key_bits() const {
   const auto& priv = m_private->key();
   const secure_vector<uint8_t> bits(priv.begin(), priv.begin() + 32);
   return DER_Encoder().encode(bits, ASN1_Type::OctetString).get_contents();
}

bool Ed25519_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   std::vector<uint8_t> public_point(32);
   secure_vector<uint8_t> private_key(64);  // discarded
   ed25519_gen_keypair(public_point.data(), private_key.data(), m_private->key().data());
   // Variable time comparison is fine here
   return public_point == m_public->key();
}

namespace {

/**
* Ed25519 verifying operation
*/
class Ed25519_Pure_Verify_Operation final : public PK_Ops::Verification {
   public:
      explicit Ed25519_Pure_Verify_Operation(std::shared_ptr<const Ed25519_PublicKey_Data> key) :
            m_key(std::move(key)) {}

      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         if(sig.size() != 64) {
            m_msg.clear();
            return false;
         }

         const auto& key = m_key->key();
         BOTAN_ASSERT_EQUAL(key.size(), 32, "Expected size");
         const bool ok = ed25519_verify(m_msg.data(), m_msg.size(), sig.data(), key.data(), nullptr, 0);
         m_msg.clear();
         return ok;
      }

      std::string hash_function() const override { return "SHA-512"; }

   private:
      std::vector<uint8_t> m_msg;
      std::shared_ptr<const Ed25519_PublicKey_Data> m_key;
};

/**
* Ed25519 verifying operation with pre-hash
*/
class Ed25519_Hashed_Verify_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      Ed25519_Hashed_Verify_Operation(std::shared_ptr<const Ed25519_PublicKey_Data> key,
                                      std::string_view hash,
                                      bool rfc8032) :
            PK_Ops::Verification_with_Hash(hash), m_key(std::move(key)) {
         if(rfc8032) {
            m_domain_sep = {0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E,
                            0x6F, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F,
                            0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73, 0x01, 0x00};
         }
      }

      bool verify(std::span<const uint8_t> ph, std::span<const uint8_t> sig) override {
         if(sig.size() != 64) {
            return false;
         }

         const auto& key = m_key->key();
         BOTAN_ASSERT_EQUAL(key.size(), 32, "Expected size");
         return ed25519_verify(ph.data(), ph.size(), sig.data(), key.data(), m_domain_sep.data(), m_domain_sep.size());
      }

   private:
      std::shared_ptr<const Ed25519_PublicKey_Data> m_key;
      std::vector<uint8_t> m_domain_sep;
};

/**
* Ed25519 signing operation ('pure' - signs message directly)
*/
class Ed25519_Pure_Sign_Operation final : public PK_Ops::Signature {
   public:
      explicit Ed25519_Pure_Sign_Operation(std::shared_ptr<const Ed25519_PrivateKey_Data> key) :
            m_key(std::move(key)) {}

      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         std::vector<uint8_t> sig(64);
         const auto& key = m_key->key();
         ed25519_sign(sig.data(), m_msg.data(), m_msg.size(), key.data(), nullptr, 0);
         m_msg.clear();
         return sig;
      }

      size_t signature_length() const override { return 64; }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return "SHA-512"; }

   private:
      std::vector<uint8_t> m_msg;
      std::shared_ptr<const Ed25519_PrivateKey_Data> m_key;
};

AlgorithmIdentifier Ed25519_Pure_Sign_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("Ed25519"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

/**
* Ed25519 signing operation with pre-hash
*/
class Ed25519_Hashed_Sign_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      Ed25519_Hashed_Sign_Operation(std::shared_ptr<const Ed25519_PrivateKey_Data> key,
                                    std::string_view hash,
                                    bool rfc8032) :
            PK_Ops::Signature_with_Hash(hash), m_key(std::move(key)) {
         if(rfc8032) {
            m_domain_sep = std::vector<uint8_t>{0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E,
                                                0x6F, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F,
                                                0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73, 0x01, 0x00};
         }
      }

      size_t signature_length() const override { return 64; }

      std::vector<uint8_t> raw_sign(std::span<const uint8_t> ph, RandomNumberGenerator& /*rng*/) override {
         std::vector<uint8_t> sig(64);
         const auto& key = m_key->key();
         ed25519_sign(sig.data(), ph.data(), ph.size(), key.data(), m_domain_sep.data(), m_domain_sep.size());
         return sig;
      }

   private:
      std::shared_ptr<const Ed25519_PrivateKey_Data> m_key;
      std::vector<uint8_t> m_domain_sep;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> Ed25519_PublicKey::create_verification_op(std::string_view params,
                                                                                std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(params.empty() || params == "Identity" || params == "Pure") {
         return std::make_unique<Ed25519_Pure_Verify_Operation>(m_public);
      } else if(params == "Ed25519ph") {
         return std::make_unique<Ed25519_Hashed_Verify_Operation>(m_public, "SHA-512", true);
      } else {
         return std::make_unique<Ed25519_Hashed_Verify_Operation>(m_public, params, false);
      }
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> Ed25519_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                     std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Ed25519 X509 signature");
      }

      return std::make_unique<Ed25519_Pure_Verify_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> Ed25519_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                           std::string_view params,
                                                                           std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(params.empty() || params == "Identity" || params == "Pure") {
         return std::make_unique<Ed25519_Pure_Sign_Operation>(m_private);
      } else if(params == "Ed25519ph") {
         return std::make_unique<Ed25519_Hashed_Sign_Operation>(m_private, "SHA-512", true);
      } else {
         return std::make_unique<Ed25519_Hashed_Sign_Operation>(m_private, params, false);
      }
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
