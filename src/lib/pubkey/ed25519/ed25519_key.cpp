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

AlgorithmIdentifier Ed25519_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool Ed25519_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   if(m_public.size() != 32) {
      return false;
   }

   /*
   This function was derived from public domain code in Tor's blinding.c
   */

   const uint8_t identity_element[32] = {1};
   if(CT::is_equal(m_public.data(), identity_element, 32).as_bool()) {
      return false;
   }

   // The order of the Ed25519 group encoded
   const uint8_t modm_m[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                               0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

   const unsigned char zero[32] = {0};

   unsigned char pkcopy[32];

   copy_mem(pkcopy, m_public.data(), 32);
   pkcopy[31] ^= (1 << 7);  // flip sign

   return signature_check(pkcopy, modm_m, identity_element, zero);
}

Ed25519_PublicKey::Ed25519_PublicKey(const uint8_t pub_key[], size_t pub_len) {
   if(pub_len != 32) {
      throw Decoding_Error("Invalid length for Ed25519 key");
   }
   m_public.assign(pub_key, pub_key + pub_len);
}

Ed25519_PublicKey::Ed25519_PublicKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) {
   m_public.assign(key_bits.begin(), key_bits.end());

   if(m_public.size() != 32) {
      throw Decoding_Error("Invalid size for Ed25519 public key");
   }
}

std::vector<uint8_t> Ed25519_PublicKey::raw_public_key_bits() const {
   return m_public;
}

std::vector<uint8_t> Ed25519_PublicKey::public_key_bits() const {
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> Ed25519_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Ed25519_PrivateKey>(rng);
}

Ed25519_PrivateKey::Ed25519_PrivateKey(std::span<const uint8_t> secret_key) {
   if(secret_key.size() == 64) {
      m_private.assign(secret_key.begin(), secret_key.end());
      m_public.assign(m_private.begin() + 32, m_private.end());
   } else if(secret_key.size() == 32) {
      m_public.resize(32);
      m_private.resize(64);
      ed25519_gen_keypair(m_public.data(), m_private.data(), secret_key.data());
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
   m_public.resize(32);
   m_private.resize(64);
   ed25519_gen_keypair(m_public.data(), m_private.data(), seed.data());
}

Ed25519_PrivateKey::Ed25519_PrivateKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) {
   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits).decode(bits, ASN1_Type::OctetString).discard_remaining();

   if(bits.size() != 32) {
      throw Decoding_Error("Invalid size for Ed25519 private key");
   }
   m_public.resize(32);
   m_private.resize(64);
   ed25519_gen_keypair(m_public.data(), m_private.data(), bits.data());
}

std::unique_ptr<Public_Key> Ed25519_PrivateKey::public_key() const {
   return std::make_unique<Ed25519_PublicKey>(get_public_key());
}

secure_vector<uint8_t> Ed25519_PrivateKey::private_key_bits() const {
   secure_vector<uint8_t> bits(m_private.data(), &m_private[32]);
   return DER_Encoder().encode(bits, ASN1_Type::OctetString).get_contents();
}

bool Ed25519_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   return true;  // ???
}

namespace {

/**
* Ed25519 verifying operation
*/
class Ed25519_Pure_Verify_Operation final : public PK_Ops::Verification {
   public:
      explicit Ed25519_Pure_Verify_Operation(const Ed25519_PublicKey& key) : m_key(key.get_public_key()) {}

      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         if(sig.size() != 64) {
            return false;
         }

         BOTAN_ASSERT_EQUAL(m_key.size(), 32, "Expected size");
         const bool ok = ed25519_verify(m_msg.data(), m_msg.size(), sig.data(), m_key.data(), nullptr, 0);
         m_msg.clear();
         return ok;
      }

      std::string hash_function() const override { return "SHA-512"; }

   private:
      std::vector<uint8_t> m_msg;
      std::vector<uint8_t> m_key;
};

/**
* Ed25519 verifying operation with pre-hash
*/
class Ed25519_Hashed_Verify_Operation final : public PK_Ops::Verification {
   public:
      Ed25519_Hashed_Verify_Operation(const Ed25519_PublicKey& key, std::string_view hash, bool rfc8032) :
            m_key(key.get_public_key()) {
         m_hash = HashFunction::create_or_throw(hash);

         if(rfc8032) {
            m_domain_sep = {0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E,
                            0x6F, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F,
                            0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73, 0x01, 0x00};
         }
      }

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         if(sig.size() != 64) {
            return false;
         }
         std::vector<uint8_t> msg_hash(m_hash->output_length());
         m_hash->final(msg_hash.data());

         BOTAN_ASSERT_EQUAL(m_key.size(), 32, "Expected size");
         return ed25519_verify(
            msg_hash.data(), msg_hash.size(), sig.data(), m_key.data(), m_domain_sep.data(), m_domain_sep.size());
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_key;
      std::vector<uint8_t> m_domain_sep;
};

/**
* Ed25519 signing operation ('pure' - signs message directly)
*/
class Ed25519_Pure_Sign_Operation final : public PK_Ops::Signature {
   public:
      explicit Ed25519_Pure_Sign_Operation(const Ed25519_PrivateKey& key) : m_key(key.raw_private_key_bits()) {}

      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         std::vector<uint8_t> sig(64);
         ed25519_sign(sig.data(), m_msg.data(), m_msg.size(), m_key.data(), nullptr, 0);
         m_msg.clear();
         return sig;
      }

      size_t signature_length() const override { return 64; }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return "SHA-512"; }

   private:
      std::vector<uint8_t> m_msg;
      secure_vector<uint8_t> m_key;
};

AlgorithmIdentifier Ed25519_Pure_Sign_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("Ed25519"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

/**
* Ed25519 signing operation with pre-hash
*/
class Ed25519_Hashed_Sign_Operation final : public PK_Ops::Signature {
   public:
      Ed25519_Hashed_Sign_Operation(const Ed25519_PrivateKey& key, std::string_view hash, bool rfc8032) :
            m_key(key.raw_private_key_bits()) {
         m_hash = HashFunction::create_or_throw(hash);

         if(rfc8032) {
            m_domain_sep = std::vector<uint8_t>{0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E,
                                                0x6F, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F,
                                                0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73, 0x01, 0x00};
         }
      }

      size_t signature_length() const override { return 64; }

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         std::vector<uint8_t> sig(64);
         std::vector<uint8_t> msg_hash(m_hash->output_length());
         m_hash->final(msg_hash.data());
         ed25519_sign(
            sig.data(), msg_hash.data(), msg_hash.size(), m_key.data(), m_domain_sep.data(), m_domain_sep.size());
         return sig;
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::unique_ptr<HashFunction> m_hash;
      secure_vector<uint8_t> m_key;
      std::vector<uint8_t> m_domain_sep;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> Ed25519_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   BOTAN_ARG_CHECK(!options.using_padding(), "Ed25519 does not support padding");

   if(!options.using_provider()) {
      if(options.using_prehash()) {
         if(options.prehash_fn().has_value()) {
            return std::make_unique<Ed25519_Hashed_Verify_Operation>(*this, options.prehash_fn().value(), false);
         } else {
            return std::make_unique<Ed25519_Hashed_Verify_Operation>(*this, "SHA-512", true);
         }
      } else {
         return std::make_unique<Ed25519_Pure_Verify_Operation>(*this);
      }
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
}

std::unique_ptr<PK_Ops::Verification> Ed25519_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                     std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Ed25519 X509 signature");
      }

      return std::make_unique<Ed25519_Pure_Verify_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> Ed25519_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                            const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   BOTAN_ARG_CHECK(!options.using_padding(), "Ed25519 does not support padding");
   BOTAN_ARG_CHECK(!options.using_salt_size(), "Ed25519 does not support a salt");

   if(!options.using_provider()) {
      if(options.using_prehash()) {
         if(options.prehash_fn().has_value()) {
            return std::make_unique<Ed25519_Hashed_Sign_Operation>(*this, options.prehash_fn().value(), false);
         } else {
            return std::make_unique<Ed25519_Hashed_Sign_Operation>(*this, "SHA-512", true);
         }
      } else {
         return std::make_unique<Ed25519_Pure_Sign_Operation>(*this);
      }
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
}

}  // namespace Botan
