/**
 * Adapter that allows using an asymmetric encryption key (typically RSA) as a
 * KEM by encrypting a symmetric key.
 *
 * (C) 2026 Jack Lloyd
 *     2026 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ASYMMETRIC_ENCRYPTION_TO_KEM_ADAPTER_H_
#define BOTAN_ASYMMETRIC_ENCRYPTION_TO_KEM_ADAPTER_H_

#include <botan/pubkey.h>

#include <memory>
#include <string_view>

namespace Botan {

/**
 * Adapter to use an asymmetric encryption key (typically RSA) as a key
 * encapsulation mechanism (KEM). This works by encrypting a random symmetric
 * key using the asymmetric encryption operation.
 */
class BOTAN_TEST_API Asymmetric_Encryption_to_KEM_Adapter_PublicKey : public virtual Public_Key {
   public:
      explicit Asymmetric_Encryption_to_KEM_Adapter_PublicKey(std::unique_ptr<Public_Key> public_key,
                                                              std::string_view padding);

      std::string algo_name() const override;
      size_t estimated_strength() const override;
      size_t key_length() const override;
      bool check_key(RandomNumberGenerator& rng, bool strong) const override;
      AlgorithmIdentifier algorithm_identifier() const override;
      std::vector<uint8_t> raw_public_key_bits() const override;
      std::vector<uint8_t> public_key_bits() const override;
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override;

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(
         std::string_view kdf, std::string_view provider = "base") const override;

      const Public_Key& inner() const { return *m_public_key; }

   protected:
      const std::string& padding() const { return m_padding; }

   private:
      std::shared_ptr<const Public_Key> m_public_key;
      std::string m_padding;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * Adapter to use an asymmetric encryption key (typically RSA) as a key
 * encapsulation mechanism (KEM). This works by encrypting a random symmetric
 * key using the asymmetric encryption operation.
 */
class BOTAN_TEST_API Asymmetric_Encryption_to_KEM_Adapter_PrivateKey final
      : public Asymmetric_Encryption_to_KEM_Adapter_PublicKey,
        public virtual Private_Key {
   public:
      explicit Asymmetric_Encryption_to_KEM_Adapter_PrivateKey(std::unique_ptr<Private_Key> private_key,
                                                               std::string_view padding);

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(
         RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider = "base") const override;

      const Private_Key& inner() const { return *m_private_key; }

   private:
      std::unique_ptr<Private_Key> m_private_key;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
