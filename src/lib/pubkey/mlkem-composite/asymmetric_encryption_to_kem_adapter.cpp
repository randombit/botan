/**
 * Asymmetric-Encrypiton-to-KEM Adapter
 *
 * (C) 2026 Jack Lloyd
 *     2026 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/asymmetric_encryption_to_kem_adapter.h>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

namespace {

constexpr size_t shared_secret_length = 32;

std::unique_ptr<Public_Key> maybe_get_public_key(const std::unique_ptr<Private_Key>& private_key) {
   BOTAN_ARG_CHECK(private_key != nullptr, "Asymmetric-Encryption-to-KEM Adapter: private key is a nullptr");
   return private_key->public_key();
}

class Asymmetric_Encryption_to_KEM_Encryption_Operation final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      Asymmetric_Encryption_to_KEM_Encryption_Operation(const Public_Key& key,
                                                        std::string_view padding,
                                                        std::string_view kdf,
                                                        std::string_view provider) :
            PK_Ops::KEM_Encryption_with_KDF(kdf), m_encryptor(key, m_null_rng, padding, provider) {}

      size_t raw_kem_shared_key_length() const override { return shared_secret_length; }

      size_t encapsulated_key_length() const override { return m_encryptor.ciphertext_length(shared_secret_length); }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override {
         BOTAN_ARG_CHECK(raw_shared_key.size() == shared_secret_length,
                         "Asymmetric-Encryption-to-KEM Adapter: shared key out-param has incorrect length");
         BOTAN_ARG_CHECK(out_encapsulated_key.size() == encapsulated_key_length(),
                         "Asymmetric-Encryption-to-KEM Adapter: encapsulated key out-param has incorrect length");

         rng.randomize(raw_shared_key);

         // TODO: It would be great to have an out-param overload of
         //       PK_Encryptor_EME::encrypt() to avoid the allocation.
         const auto encapsulated_key = m_encryptor.encrypt(raw_shared_key, rng);

         BOTAN_ASSERT_EQUAL(encapsulated_key.size(),
                            out_encapsulated_key.size(),
                            "Asymmetric-Encryption-to-KEM Adapter: shared key out-param has correct length");
         copy_mem(out_encapsulated_key, encapsulated_key);
      }

   private:
      Null_RNG m_null_rng;
      PK_Encryptor_EME m_encryptor;
};

class Asymmetric_Encryption_to_KEM_Decryption_Operation final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      Asymmetric_Encryption_to_KEM_Decryption_Operation(const Private_Key& key,
                                                        RandomNumberGenerator& rng,
                                                        std::string_view padding,
                                                        std::string_view kdf,
                                                        std::string_view provider) :
            PK_Ops::KEM_Decryption_with_KDF(kdf), m_decryptor(key, rng, padding, provider) {}

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encap_key) override {
         BOTAN_ARG_CHECK(out_shared_key.size() == shared_secret_length,
                         "Asymmetric-Encryption-to-KEM Adapter: shared key out-param has incorrect length");
         BOTAN_ARG_CHECK(encap_key.size() == encapsulated_key_length(),
                         "Asymmetric-Encryption-to-KEM Adapter: encapsulated key param has incorrect length");

         // TODO: It would be great to have an out-param overload of
         //       PK_Decryptor_EME::decrypt() to avoid the allocation.
         const auto shared_key = m_decryptor.decrypt(encap_key);

         BOTAN_ASSERT_EQUAL(shared_key.size(),
                            out_shared_key.size(),
                            "Asymmetric-Encryption-to-KEM Adapter: shared key out-param has correct length");
         copy_mem(out_shared_key, shared_key);
      }

      size_t encapsulated_key_length() const override { return m_decryptor.ciphertext_length(shared_secret_length); }

      size_t raw_kem_shared_key_length() const override { return shared_secret_length; }

   private:
      PK_Decryptor_EME m_decryptor;
};

}  // namespace

Asymmetric_Encryption_to_KEM_Adapter_PublicKey::Asymmetric_Encryption_to_KEM_Adapter_PublicKey(
   std::unique_ptr<Public_Key> public_key, std::string_view padding) :
      m_public_key(std::move(public_key)), m_padding(padding) {
   BOTAN_ARG_CHECK(m_public_key != nullptr, "Asymmetric-Encryption-to-KEM Adapter: public key is a nullptr");
   BOTAN_ARG_CHECK(m_public_key->supports_operation(PublicKeyOperation::Encryption),
                   "Asymmetric-Encryption-to-KEM Adapter: public key does not implement encryption");
}

std::string Asymmetric_Encryption_to_KEM_Adapter_PublicKey::algo_name() const {
   return fmt("Asymmetric-Encryption-to-KEM({})", m_public_key->algo_name());
}

size_t Asymmetric_Encryption_to_KEM_Adapter_PublicKey::estimated_strength() const {
   return m_public_key->estimated_strength();
}

size_t Asymmetric_Encryption_to_KEM_Adapter_PublicKey::key_length() const {
   return m_public_key->key_length();
}

bool Asymmetric_Encryption_to_KEM_Adapter_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_public_key->check_key(rng, strong);
}

AlgorithmIdentifier Asymmetric_Encryption_to_KEM_Adapter_PublicKey::algorithm_identifier() const {
   return m_public_key->algorithm_identifier();
}

std::vector<uint8_t> Asymmetric_Encryption_to_KEM_Adapter_PublicKey::raw_public_key_bits() const {
   return m_public_key->raw_public_key_bits();
}

std::vector<uint8_t> Asymmetric_Encryption_to_KEM_Adapter_PublicKey::public_key_bits() const {
   return m_public_key->public_key_bits();
}

std::unique_ptr<Private_Key> Asymmetric_Encryption_to_KEM_Adapter_PublicKey::generate_another(
   RandomNumberGenerator& rng) const {
   return std::make_unique<Asymmetric_Encryption_to_KEM_Adapter_PrivateKey>(m_public_key->generate_another(rng),
                                                                            m_padding);
}

bool Asymmetric_Encryption_to_KEM_Adapter_PublicKey::supports_operation(PublicKeyOperation op) const {
   return op == PublicKeyOperation::KeyEncapsulation;
}

Asymmetric_Encryption_to_KEM_Adapter_PrivateKey::Asymmetric_Encryption_to_KEM_Adapter_PrivateKey(
   std::unique_ptr<Private_Key> private_key, std::string_view padding) :
      Asymmetric_Encryption_to_KEM_Adapter_PublicKey(maybe_get_public_key(private_key), padding),
      m_private_key(std::move(private_key)) {}

secure_vector<uint8_t> Asymmetric_Encryption_to_KEM_Adapter_PrivateKey::private_key_bits() const {
   return m_private_key->private_key_bits();
}

secure_vector<uint8_t> Asymmetric_Encryption_to_KEM_Adapter_PrivateKey::raw_private_key_bits() const {
   return m_private_key->raw_private_key_bits();
}

std::unique_ptr<Public_Key> Asymmetric_Encryption_to_KEM_Adapter_PrivateKey::public_key() const {
   return std::make_unique<Asymmetric_Encryption_to_KEM_Adapter_PublicKey>(m_private_key->public_key(), padding());
}

bool Asymmetric_Encryption_to_KEM_Adapter_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_private_key->check_key(rng, strong);
}

std::unique_ptr<PK_Ops::KEM_Encryption> Asymmetric_Encryption_to_KEM_Adapter_PublicKey::create_kem_encryption_op(
   std::string_view kdf, std::string_view provider) const {
   return std::make_unique<Asymmetric_Encryption_to_KEM_Encryption_Operation>(*m_public_key, padding(), kdf, provider);
}

std::unique_ptr<PK_Ops::KEM_Decryption> Asymmetric_Encryption_to_KEM_Adapter_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider) const {
   return std::make_unique<Asymmetric_Encryption_to_KEM_Decryption_Operation>(
      *m_private_key, rng, padding(), kdf, provider);
}

}  // namespace Botan
