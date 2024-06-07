/**
 * Adapter that allows using a KEX key as a KEM, using an ephemeral
 * key in the KEM encapsulation.
 *
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kex_to_kem_adapter.h>

#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include <botan/dh.h>
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_ECDH)
   #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

namespace Botan::TLS {

namespace {

/**
 * This helper determines the length of the agreed-upon value depending
 * on the key agreement public key's algorithm type. It would be better
 * to get this value via PK_Key_Agreement::agreed_value_size(), but
 * instantiating a PK_Key_Agreement object requires a PrivateKey object
 * which we don't have (yet) in the context this is used.
 *
 * TODO: Find a way to get this information without duplicating those
 *       implementation details of the key agreement algorithms.
 */
size_t kex_shared_key_length(const Public_Key& kex_public_key) {
   BOTAN_ASSERT_NOMSG(kex_public_key.supports_operation(PublicKeyOperation::KeyAgreement));

#if defined(BOTAN_HAS_ECDH)
   if(const auto* ecdh = dynamic_cast<const ECDH_PublicKey*>(&kex_public_key)) {
      return ecdh->domain().get_p_bytes();
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(const auto* dh = dynamic_cast<const DH_PublicKey*>(&kex_public_key)) {
      return dh->group().p_bytes();
   }
#endif

#if defined(BOTAN_HAS_X25519)
   if(const auto* curve = dynamic_cast<const X25519_PublicKey*>(&kex_public_key)) {
      BOTAN_UNUSED(curve);
      return 32; /* TODO: magic number */
   }
#endif

#if defined(BOTAN_HAS_X448)
   if(const auto* curve = dynamic_cast<const X448_PublicKey*>(&kex_public_key)) {
      BOTAN_UNUSED(curve);
      return 56; /* TODO: magic number */
   }
#endif

   throw Not_Implemented(
      fmt("Cannot get shared kex key length from unknown key agreement public key of type '{}' in the hybrid KEM key",
          kex_public_key.algo_name()));
}

/**
 * This helper generates an ephemeral key agreement private key given a
 * public key instance of a certain key agreement algorithm.
 */
std::unique_ptr<PK_Key_Agreement_Key> generate_key_agreement_private_key(const Public_Key& kex_public_key,
                                                                         RandomNumberGenerator& rng) {
   BOTAN_ASSERT_NOMSG(kex_public_key.supports_operation(PublicKeyOperation::KeyAgreement));

   auto new_kex_key = [&] {
      auto new_private_key = kex_public_key.generate_another(rng);
      const auto kex_key = dynamic_cast<PK_Key_Agreement_Key*>(new_private_key.get());
      if(kex_key) [[likely]] {
         // Intentionally leak new_private_key since we hold an alias of it in kex_key,
         // which is captured in a unique_ptr below
         // NOLINTNEXTLINE(*-unused-return-value)
         (void)new_private_key.release();
      }
      return std::unique_ptr<PK_Key_Agreement_Key>(kex_key);
   }();

   BOTAN_ASSERT(new_kex_key, "Keys wrapped in this adapter are always key-agreement keys");
   return new_kex_key;
}

std::unique_ptr<Public_Key> maybe_get_public_key(const std::unique_ptr<PK_Key_Agreement_Key>& private_key) {
   BOTAN_ARG_CHECK(private_key != nullptr, "Private key is a nullptr");
   return private_key->public_key();
}

class KEX_to_KEM_Adapter_Encryption_Operation final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      KEX_to_KEM_Adapter_Encryption_Operation(const Public_Key& key, std::string_view kdf, std::string_view provider) :
            PK_Ops::KEM_Encryption_with_KDF(kdf), m_provider(provider), m_public_key(key) {}

      size_t raw_kem_shared_key_length() const override { return kex_shared_key_length(m_public_key); }

      size_t encapsulated_key_length() const override {
         // Serializing the public value into a short-lived heap-allocated
         // vector is not ideal.
         //
         // TODO: Find a way to get the public value length without copying
         //       the public value into a vector. See GH #3706 (point 5).
         return m_public_key.raw_public_key_bits().size();
      }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override {
         const auto sk = generate_key_agreement_private_key(m_public_key, rng);
         const auto shared_key = PK_Key_Agreement(*sk, rng, "Raw", m_provider)
                                    .derive_key(0 /* no KDF */, m_public_key.raw_public_key_bits())
                                    .bits_of();

         const auto public_value = sk->public_value();

         // TODO: perhaps avoid these copies by providing std::span out-params
         //       for `PK_Key_Agreement::derive_key()` and
         //       `PK_Key_Agreement_Key::public_value()`
         BOTAN_ASSERT_EQUAL(public_value.size(),
                            out_encapsulated_key.size(),
                            "KEX-to-KEM Adapter: encapsulated key out-param has correct length");
         BOTAN_ASSERT_EQUAL(
            shared_key.size(), raw_shared_key.size(), "KEX-to-KEM Adapter: shared key out-param has correct length");
         std::copy(public_value.begin(), public_value.end(), out_encapsulated_key.begin());
         std::copy(shared_key.begin(), shared_key.end(), raw_shared_key.begin());
      }

   private:
      std::string m_provider;
      const Public_Key& m_public_key;
};

class KEX_to_KEM_Decryption_Operation final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      KEX_to_KEM_Decryption_Operation(const PK_Key_Agreement_Key& key,
                                      RandomNumberGenerator& rng,
                                      const std::string_view kdf,
                                      const std::string_view provider) :
            PK_Ops::KEM_Decryption_with_KDF(kdf),
            m_operation(key, rng, "Raw", provider),
            m_encapsulated_key_length(key.public_value().size()) {}

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encap_key) override {
         secure_vector<uint8_t> shared_secret = m_operation.derive_key(0 /* no KDF */, encap_key).bits_of();
         BOTAN_ASSERT_EQUAL(
            shared_secret.size(), out_shared_key.size(), "KEX-to-KEM Adapter: shared key out-param has correct length");
         std::copy(shared_secret.begin(), shared_secret.end(), out_shared_key.begin());
      }

      size_t encapsulated_key_length() const override { return m_encapsulated_key_length; }

      size_t raw_kem_shared_key_length() const override { return m_operation.agreed_value_size(); }

   private:
      PK_Key_Agreement m_operation;
      size_t m_encapsulated_key_length;
};

}  // namespace

KEX_to_KEM_Adapter_PublicKey::KEX_to_KEM_Adapter_PublicKey(std::unique_ptr<Public_Key> public_key) :
      m_public_key(std::move(public_key)) {
   BOTAN_ARG_CHECK(m_public_key != nullptr, "Public key is a nullptr");
   BOTAN_ARG_CHECK(m_public_key->supports_operation(PublicKeyOperation::KeyAgreement), "Public key is no KEX key");
}

std::string KEX_to_KEM_Adapter_PublicKey::algo_name() const {
   return fmt("KEX-to-KEM({})", m_public_key->algo_name());
}

size_t KEX_to_KEM_Adapter_PublicKey::estimated_strength() const {
   return m_public_key->estimated_strength();
}

size_t KEX_to_KEM_Adapter_PublicKey::key_length() const {
   return m_public_key->key_length();
}

bool KEX_to_KEM_Adapter_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_public_key->check_key(rng, strong);
}

AlgorithmIdentifier KEX_to_KEM_Adapter_PublicKey::algorithm_identifier() const {
   return m_public_key->algorithm_identifier();
}

std::vector<uint8_t> KEX_to_KEM_Adapter_PublicKey::raw_public_key_bits() const {
   return m_public_key->raw_public_key_bits();
}

std::vector<uint8_t> KEX_to_KEM_Adapter_PublicKey::public_key_bits() const {
   throw Not_Implemented("The KEX-to-KEM adapter does not support ASN.1-based public key serialization");
}

std::unique_ptr<Private_Key> KEX_to_KEM_Adapter_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(generate_key_agreement_private_key(*m_public_key, rng));
}

bool KEX_to_KEM_Adapter_PublicKey::supports_operation(PublicKeyOperation op) const {
   return op == PublicKeyOperation::KeyEncapsulation;
}

KEX_to_KEM_Adapter_PrivateKey::KEX_to_KEM_Adapter_PrivateKey(std::unique_ptr<PK_Key_Agreement_Key> private_key) :
      KEX_to_KEM_Adapter_PublicKey(maybe_get_public_key(private_key)), m_private_key(std::move(private_key)) {
   BOTAN_ARG_CHECK(m_private_key->supports_operation(PublicKeyOperation::KeyAgreement), "Private key is no KEX key");
}

secure_vector<uint8_t> KEX_to_KEM_Adapter_PrivateKey::private_key_bits() const {
   return m_private_key->private_key_bits();
}

std::unique_ptr<Public_Key> KEX_to_KEM_Adapter_PrivateKey::public_key() const {
   return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(m_private_key->public_key());
}

bool KEX_to_KEM_Adapter_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_private_key->check_key(rng, strong);
}

std::unique_ptr<PK_Ops::KEM_Encryption> KEX_to_KEM_Adapter_PublicKey::create_kem_encryption_op(
   std::string_view kdf, std::string_view provider) const {
   return std::make_unique<KEX_to_KEM_Adapter_Encryption_Operation>(*m_public_key, kdf, provider);
}

std::unique_ptr<PK_Ops::KEM_Decryption> KEX_to_KEM_Adapter_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider) const {
   return std::make_unique<KEX_to_KEM_Decryption_Operation>(*m_private_key, rng, kdf, provider);
}

}  // namespace Botan::TLS
