/*
* TPM 2.0 RSA Key Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_RSA_H_
#define BOTAN_TPM2_RSA_H_

#include <botan/rsa.h>
#include <botan/tpm2_key.h>

namespace Botan::TPM2 {

/**
 * This helper function transforms a @p public_blob in a TPM2B_PUBLIC* format
 * into the functional components of an RSA public key. Namely, a pair of
 * modulus and exponent as big integers.
 *
 * @param public_blob The public blob to decompose into RSA pubkey components
 */
std::pair<BigInt, BigInt> rsa_pubkey_components_from_tss2_public(const TPM2B_PUBLIC* public_blob);

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 6) RSA_PublicKey final : public virtual Botan::TPM2::PublicKey,
                                                   public virtual Botan::RSA_PublicKey {
   public:
      std::unique_ptr<Private_Key> generate_another(Botan::RandomNumberGenerator& rng) const override {
         return TPM2::PublicKey::generate_another(rng);
      }

      std::vector<uint8_t> raw_public_key_bits() const override { return TPM2::PublicKey::raw_public_key_bits(); }

      bool supports_operation(PublicKeyOperation op) const override {
         // TODO: Support RSA-KEM
         return op == PublicKeyOperation::Encryption || op == PublicKeyOperation::Signature;
      }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Encryption> create_encryption_op(Botan::RandomNumberGenerator& rng,
                                                               std::string_view params,
                                                               std::string_view provider) const override;

   protected:
      friend class TPM2::PublicKey;

      RSA_PublicKey(Object handle, SessionBundle sessions, const TPM2B_PUBLIC* public_blob);

   private:
      /**
       * This constructor is delegated to from the other (protected) constructor
       * to avoid calling the subclass' RSA_PublicKey's copy/move constructor
       * during initialization. This is to work around an apparent issue in MSVC
       * leading to a heap corruption.
       */
      RSA_PublicKey(Object handle, SessionBundle sessions, const std::pair<BigInt, BigInt>& pubkey);
};

class BOTAN_PUBLIC_API(3, 6) RSA_PrivateKey final : public virtual Botan::TPM2::PrivateKey,
                                                    public virtual Botan::RSA_PublicKey {
   public:
      /**
       * Create a transient RSA key with the given @p keylength and @p exponent,
       * under the given @p parent key, with the given @p auth_value. This key
       * may be used for both signatures and data decryption. No restrictions
       * on the utilized padding schemes are applied.
       *
       * TODO: provide the user with some means to specify such restrictions:
       *         - allowed key use: sign, decrypt, sign+decrypt, x509sign
       *         - allowed padding schemes: PKCS1v1.5, OAEP, PSS
       *         - data restrictions ("restricted" field in TPMT_PUBLIC)
       *         - session authentication requirements (policy, user authentication, ...)
       *         - fixed to TPM, or fixed to parent?
       *         - ...
       *
       * @param ctx The TPM context to use
       * @param sessions The session bundle to use in the creation of the key
       * @param auth_value The auth value to use for the key
       * @param parent The parent key to create the new key under
       * @param keylength The desired key length
       * @param exponent The desired exponent (default: 0x10001)
       */
      static std::unique_ptr<TPM2::PrivateKey> create_unrestricted_transient(const std::shared_ptr<Context>& ctx,
                                                                             const SessionBundle& sessions,
                                                                             std::span<const uint8_t> auth_value,
                                                                             const TPM2::PrivateKey& parent,
                                                                             uint16_t keylength,
                                                                             std::optional<uint32_t> exponent = {});

   public:
      std::unique_ptr<Public_Key> public_key() const override {
         return std::make_unique<Botan::RSA_PublicKey>(algorithm_identifier(), public_key_bits());
      }

      std::vector<uint8_t> raw_public_key_bits() const override { return TPM2::PrivateKey::raw_public_key_bits(); }

      bool supports_operation(PublicKeyOperation op) const override {
         // TODO: Support RSA-KEM
         return op == PublicKeyOperation::Encryption || op == PublicKeyOperation::Signature;
      }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(Botan::RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Decryption> create_decryption_op(Botan::RandomNumberGenerator& rng,
                                                               std::string_view params,
                                                               std::string_view provider) const override;

   protected:
      friend class TPM2::PrivateKey;

      RSA_PrivateKey(Object handle,
                     SessionBundle sessions,
                     const TPM2B_PUBLIC* public_blob,
                     std::span<const uint8_t> private_blob = {});

   private:
      /**
       * This constructor is delegated to from the other (protected) constructor
       * to avoid calling the subclass' RSA_PublicKey's copy/move constructor
       * during initialization. This is to work around an apparent issue in MSVC
       * leading to a heap corruption.
       */
      RSA_PrivateKey(Object handle,
                     SessionBundle sessions,
                     const std::pair<BigInt, BigInt>& pubkey,
                     std::span<const uint8_t> private_blob = {});
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
