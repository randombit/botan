/**
 * Adapter that allows using a KEX key as a KEM, using an ephemeral
 * key in the KEM encapsulation.
 *
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_13_KEX_TO_KEM_ADAPTER_H_
#define BOTAN_TLS_13_KEX_TO_KEM_ADAPTER_H_

#include <botan/pubkey.h>

#include <memory>

namespace Botan::TLS {

/**
 * Adapter to use a key agreement key pair (e.g. ECDH) as a key encapsulation
 * mechanism.
 */
class BOTAN_TEST_API KEX_to_KEM_Adapter_PublicKey : public virtual Public_Key {
   public:
      KEX_to_KEM_Adapter_PublicKey(std::unique_ptr<Public_Key> public_key);

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

   private:
      std::unique_ptr<Public_Key> m_public_key;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * Adapter to use a key agreement key pair (e.g. ECDH) as a key encapsulation
 * mechanism. This works by generating an ephemeral key pair during the
 * encapsulation.
 *
 * The abstract interface of a key exchange mechanism (KEX) is mapped like so:
 *
 *  * KEM-generate(rng) -> tuple[PublicKey, PrivateKey]
 *       => KEX-generate(rng) -> tuple[PublicKey, PrivateKey]
 *
 *  * KEM-encapsulate(PublicKey, rng) -> tuple[SharedSecret, EncapsulatedSharedSecret]
 *       => eph_pk, eph_sk = KEX-generate(rng)
 *          secret         = KEX-agree(eph_sk, PublicKey)
 *          [secret, eph_pk]
 *
 *  * KEM-decapsulate(PrivateKey, EncapsulatedSharedSecret) -> SharedSecret
 *       => KEX-agree(PrivateKey, EncapsulatedSharedSecret)
 */
class BOTAN_TEST_API KEX_to_KEM_Adapter_PrivateKey final : public KEX_to_KEM_Adapter_PublicKey,
                                                           public virtual Private_Key {
   public:
      KEX_to_KEM_Adapter_PrivateKey(std::unique_ptr<PK_Key_Agreement_Key> private_key);

      secure_vector<uint8_t> private_key_bits() const override;

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(
         RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider = "base") const override;

   private:
      std::unique_ptr<PK_Key_Agreement_Key> m_private_key;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TLS

#endif
