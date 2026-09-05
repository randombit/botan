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
#include <botan/mem_ops.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ed25519_internal.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pk_options_impl.h>
#include <array>

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
   * This rejects the identity in either its canonical or non-canonical
   * encoding (the latter fails to decode), points of small order, and
   * points outside the prime order subgroup.
   */
   return ed25519_valid_public_key_point(std::span<const uint8_t, 32>{pub.data(), 32});
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

/*
* Return the secret scalar, derived by hashing the seed and clamping
* (RFC 8032 5.1.5)
*/
Ed25519_Scalar ed25519_secret_scalar(HashFunction& sha512, std::span<const uint8_t> seed) {
   std::array<uint8_t, 64> az{};
   sha512.update(seed);
   sha512.final(az);
   az[0] &= 248;
   az[31] &= 63;
   az[31] |= 64;

   const auto a = Ed25519_Scalar::from_bytes(std::span{az}.first<32>());
   secure_scrub_memory(az);
   return a;
}

// Generate the 64-byte expanded private key from a 32-byte seed.
secure_vector<uint8_t> ed25519_expand_seed(std::span<const uint8_t> seed) {
   BOTAN_ASSERT_NOMSG(seed.size() == 32);

   auto sha512 = HashFunction::create_or_throw("SHA-512");
   const auto a = ed25519_secret_scalar(*sha512, seed);

   secure_vector<uint8_t> sk(64);
   copy_mem(sk.data(), seed.data(), 32);
   ed25519_basepoint_mul(std::span<uint8_t, 32>{sk.data() + 32, 32}, a);
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
   const auto& priv = m_private->key();
   const auto regen = ed25519_expand_seed(std::span<const uint8_t>{priv.data(), 32});
   // Variable time comparison is fine here
   return std::vector<uint8_t>(regen.begin() + 32, regen.end()) == m_public->key();
}

namespace {

/*
* The dom2 prefix for Ed25519ph (RFC 8032 sections 2 and 5.1), with
* phflag 1 and an empty context
*/
std::vector<uint8_t> ed25519ph_domain_sep() {
   constexpr std::string_view prefix = "SigEd25519 no Ed25519 collisions";
   std::vector<uint8_t> ds(prefix.begin(), prefix.end());
   ds.push_back(0x01);
   ds.push_back(0x00);
   return ds;
}

/**
* Ed25519 verification, following RFC 8032 5.1.7
*
* Subclasses determine the message that is verified and the domain
* separator prepended to the hash inputs.
*/
class Ed25519_Verify_Operation_Base : public PK_Ops::Verification {
   protected:
      Ed25519_Verify_Operation_Base(std::shared_ptr<const Ed25519_PublicKey_Data> key,
                                    std::vector<uint8_t> domain_sep) :
            m_key(std::move(key)), m_domain_sep(std::move(domain_sep)) {
         BOTAN_ASSERT_EQUAL(m_key->key().size(), 32, "Expected size");

         // Reject the identity, low order points, and points outside the prime
         // order subgroup up front.
         //
         // TODO(Botan4) instead check and reject such keys during deserialization
         m_key_is_valid = ed25519_valid_public_key_point(std::span<const uint8_t, 32>{m_key->key().data(), 32});
      }

      bool verify_signature(std::span<const uint8_t> msg, std::span<const uint8_t, 64> sig) const {
         if(!m_key_is_valid) {
            return false;
         }

         const auto& pk = m_key->key();

         // RFC 8032 adds the requirement that we verify that s < order in
         // the signature; this did not exist in the original Ed25519 spec.
         const auto s = Ed25519_Scalar::from_canonical_bytes(sig.last<32>());
         if(!s) {
            return false;
         }

         std::array<uint8_t, 64> hram{};
         auto sha512 = HashFunction::create_or_throw("SHA-512");

         sha512->update(m_domain_sep);
         sha512->update(sig.data(), 32);
         sha512->update(pk);
         sha512->update(msg);
         sha512->final(hram);

         const auto h = Ed25519_Scalar::from_wide_bytes(hram);

         return ed25519_check_signature(std::span<const uint8_t, 32>{pk.data(), 32}, h, sig.data(), *s);
      }

   private:
      std::shared_ptr<const Ed25519_PublicKey_Data> m_key;
      std::vector<uint8_t> m_domain_sep;
      bool m_key_is_valid;
};

/**
* Ed25519 verifying operation
*/
class Ed25519_Pure_Verify_Operation final : public Ed25519_Verify_Operation_Base {
   public:
      explicit Ed25519_Pure_Verify_Operation(std::shared_ptr<const Ed25519_PublicKey_Data> key,
                                             std::vector<uint8_t> domain_sep = {}) :
            Ed25519_Verify_Operation_Base(std::move(key), std::move(domain_sep)) {}

      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         if(sig.size() != 64) {
            m_msg.clear();
            return false;
         }

         const bool ok = verify_signature(m_msg, sig.first<64>());
         m_msg.clear();
         return ok;
      }

      std::string hash_function() const override { return "SHA-512"; }

   private:
      std::vector<uint8_t> m_msg;
};

/**
* Ed25519 verifying operation with pre-hash
*/
class Ed25519_Hashed_Verify_Operation final : public Ed25519_Verify_Operation_Base {
   public:
      Ed25519_Hashed_Verify_Operation(std::shared_ptr<const Ed25519_PublicKey_Data> key,
                                      std::string_view hash,
                                      bool rfc8032) :
            Ed25519_Verify_Operation_Base(std::move(key), rfc8032 ? ed25519ph_domain_sep() : std::vector<uint8_t>{}),
            m_hash(HashFunction::create_or_throw(hash)) {}

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         std::vector<uint8_t> msg_hash(m_hash->output_length());
         m_hash->final(msg_hash.data());

         if(sig.size() != 64) {
            return false;
         }

         return verify_signature(msg_hash, sig.first<64>());
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::unique_ptr<HashFunction> m_hash;
};

/**
* Ed25519 signing, following RFC 8032 5.1.6
*
* Subclasses determine the message that is signed and the domain
* separator prepended to the hash inputs.
*/
class Ed25519_Sign_Operation_Base : public PK_Ops::Signature {
   public:
      size_t signature_length() const override { return 64; }

   protected:
      Ed25519_Sign_Operation_Base(std::shared_ptr<const Ed25519_PrivateKey_Data> key, std::vector<uint8_t> domain_sep) :
            m_key(std::move(key)), m_domain_sep(std::move(domain_sep)) {
         BOTAN_ASSERT_EQUAL(m_key->key().size(), 64, "Expected size");
      }

      std::vector<uint8_t> sign_message(std::span<const uint8_t> msg) const {
         const auto& sk = m_key->key();

         std::vector<uint8_t> sig_buf(64);
         const std::span<uint8_t, 64> sig(sig_buf.data(), 64);

         std::array<uint8_t, 64> hram{};

         auto sha512 = HashFunction::create_or_throw("SHA-512");

         sha512->update(sk.data(), 32);
         std::array<uint8_t, 64> az{};
         sha512->final(az);
         az[0] &= 248;
         az[31] &= 63;
         az[31] |= 64;

         const auto a = Ed25519_Scalar::from_bytes(std::span{az}.first<32>());

         std::array<uint8_t, 64> nonce{};
         sha512->update(m_domain_sep);
         sha512->update(std::span{az}.last(32));
         sha512->update(msg);
         sha512->final(nonce);

         const auto r = Ed25519_Scalar::from_wide_bytes(nonce);
         ed25519_basepoint_mul(sig.first<32>(), r);

         sha512->update(m_domain_sep);
         sha512->update(sig.first(32));
         sha512->update(sk.data() + 32, 32);
         sha512->update(msg);
         sha512->final(hram);

         const auto h = Ed25519_Scalar::from_wide_bytes(hram);

         const auto s = h * a + r;
         s.serialize_to(sig.last<32>());

         secure_scrub_memory(az);
         secure_scrub_memory(nonce);

         return sig_buf;
      }

   private:
      std::shared_ptr<const Ed25519_PrivateKey_Data> m_key;
      std::vector<uint8_t> m_domain_sep;
};

/**
* Ed25519 signing operation ('pure' - signs message directly)
*/
class Ed25519_Pure_Sign_Operation final : public Ed25519_Sign_Operation_Base {
   public:
      explicit Ed25519_Pure_Sign_Operation(std::shared_ptr<const Ed25519_PrivateKey_Data> key,
                                           std::vector<uint8_t> domain_sep = {}) :
            Ed25519_Sign_Operation_Base(std::move(key), std::move(domain_sep)) {}

      void update(std::span<const uint8_t> msg) override { m_msg.insert(m_msg.end(), msg.begin(), msg.end()); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         auto sig = sign_message(m_msg);
         m_msg.clear();
         return sig;
      }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return "SHA-512"; }

   private:
      std::vector<uint8_t> m_msg;
};

AlgorithmIdentifier Ed25519_Pure_Sign_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("Ed25519"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

/**
* Ed25519 signing operation with pre-hash
*/
class Ed25519_Hashed_Sign_Operation final : public Ed25519_Sign_Operation_Base {
   public:
      Ed25519_Hashed_Sign_Operation(std::shared_ptr<const Ed25519_PrivateKey_Data> key,
                                    std::string_view hash,
                                    bool rfc8032) :
            Ed25519_Sign_Operation_Base(std::move(key), rfc8032 ? ed25519ph_domain_sep() : std::vector<uint8_t>{}),
            m_hash(HashFunction::create_or_throw(hash)) {}

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         std::vector<uint8_t> msg_hash(m_hash->output_length());
         m_hash->final(msg_hash.data());
         return sign_message(msg_hash);
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      std::unique_ptr<HashFunction> m_hash;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> Ed25519_PublicKey::_create_verification_op(
   const PK_Signature_Options& options) const {
   if(!options.using_provider()) {
      if(options.using_prehash()) {
         if(options.prehash_function().has_value()) {
            return std::make_unique<Ed25519_Hashed_Verify_Operation>(
               m_public, options.prehash_function().value(), false);
         } else {
            return std::make_unique<Ed25519_Hashed_Verify_Operation>(m_public, "SHA-512", true);
         }
      } else {
         return std::make_unique<Ed25519_Pure_Verify_Operation>(m_public);
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

      return std::make_unique<Ed25519_Pure_Verify_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> Ed25519_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                            const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   acknowledge_always_deterministic(options);

   if(!options.using_provider()) {
      if(options.using_prehash()) {
         if(options.prehash_function().has_value()) {
            return std::make_unique<Ed25519_Hashed_Sign_Operation>(
               m_private, options.prehash_function().value(), false);
         } else {
            return std::make_unique<Ed25519_Hashed_Sign_Operation>(m_private, "SHA-512", true);
         }
      } else {
         return std::make_unique<Ed25519_Pure_Sign_Operation>(m_private);
      }
   }

   throw Provider_Not_Found(algo_name(), options.provider().value());
}

/*
* The deprecated ref10 style interface, now defined via the standard
* interfaces. An empty domain separator is ordinary Ed25519; there is no
* standard way to request an arbitrary domain separator, so that case
* drives the operation directly.
*/

void ed25519_gen_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
   const auto key = Ed25519_PrivateKey::from_seed(std::span<const uint8_t>{seed, 32});
   const auto pub_bytes = key.raw_public_key_bits();
   const auto priv_bytes = key.raw_private_key_bits();
   copy_mem(pk, pub_bytes.data(), 32);
   copy_mem(sk, priv_bytes.data(), 64);
}

void ed25519_sign(uint8_t sig[64],
                  const uint8_t msg[],
                  size_t msg_len,
                  const uint8_t sk[64],
                  const uint8_t domain_sep[],
                  size_t domain_sep_len) {
   const auto key = Ed25519_PrivateKey::from_bytes(std::span<const uint8_t>{sk, 64});

   Null_RNG null_rng;

   std::vector<uint8_t> sig_vec;
   if(domain_sep_len == 0) {
      PK_Signer signer(key, null_rng, PK_Signature_Options());
      signer.update(std::span<const uint8_t>{msg, msg_len});
      sig_vec = signer.signature(null_rng);
   } else {
      Ed25519_Pure_Sign_Operation op(std::make_shared<Ed25519_PrivateKey_Data>(key.raw_private_key_bits()),
                                     std::vector<uint8_t>(domain_sep, domain_sep + domain_sep_len));
      op.update(std::span<const uint8_t>{msg, msg_len});
      sig_vec = op.sign(null_rng);
   }

   copy_mem(sig, sig_vec.data(), 64);
}

bool ed25519_verify(const uint8_t msg[],
                    size_t msg_len,
                    const uint8_t sig[64],
                    const uint8_t pk[32],
                    const uint8_t domain_sep[],
                    size_t domain_sep_len) {
   const Ed25519_PublicKey key(std::span<const uint8_t>{pk, 32});

   if(domain_sep_len == 0) {
      PK_Verifier verifier(key, PK_Signature_Options());
      verifier.update(std::span<const uint8_t>{msg, msg_len});
      return verifier.check_signature(std::span<const uint8_t>{sig, 64});
   } else {
      Ed25519_Pure_Verify_Operation op(std::make_shared<Ed25519_PublicKey_Data>(key.raw_public_key_bits()),
                                       std::vector<uint8_t>(domain_sep, domain_sep + domain_sep_len));
      op.update(std::span<const uint8_t>{msg, msg_len});
      return op.is_valid_signature(std::span<const uint8_t>{sig, 64});
   }
}

}  // namespace Botan
