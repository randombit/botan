/*
* TPM 2.0 ECC Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_ECC_H_
#define BOTAN_TPM2_ECC_H_

#include <botan/ecdsa.h>
#include <botan/tpm2_key.h>

namespace Botan::TPM2 {

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 6) EC_PublicKey final : public virtual Botan::TPM2::PublicKey,
                                                  public virtual Botan::EC_PublicKey {
   public:
      std::string algo_name() const override { return "ECDSA"; }

      /**
       * @returns the public key encoding in ordinary point encoding
       * @sa      EC_PublicKey::set_point_encoding()
       */
      std::vector<uint8_t> public_key_bits() const override;

      /**
       * @returns the public key encoding in TPM2B_PUBLIC format
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      bool supports_operation(PublicKeyOperation op) const override {
         // TODO: ECDH/Key Agreement
         return op == PublicKeyOperation::Signature;
      }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

   protected:
      friend class TPM2::PublicKey;

      EC_PublicKey(Object handle, SessionBundle sessions, const TPM2B_PUBLIC* public_blob);
      EC_PublicKey(Object handle, SessionBundle sessions, std::pair<EC_Group, EC_AffinePoint> public_key);
};

class BOTAN_PUBLIC_API(3, 6) EC_PrivateKey final : public virtual Botan::TPM2::PrivateKey,
                                                   public virtual Botan::EC_PublicKey {
   public:
      std::string algo_name() const override {
         // TODO: Different types of ECC
         // TPM ECC keys may be used for different algorithms, so we do not always know the exact algorithm
         // because it may be used for ECDH, ECDSA, ECDAA, etc.
         // However, at least for signatures, we can say it is ECDSA since EdDSA is not supported by tpm2-tss and
         // ECDAA and ECSCHNORR are not supported by Botan.
         return "ECDSA";
      }

      std::unique_ptr<Private_Key> generate_another(Botan::RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      /**
       * Create a transient EC key with the given @p group EC Group,
       * under the given @p parent key, with the given @p auth_value.
       * This key may only be used for ECDSA signatures.
       *
       * @param ctx The TPM context to use
       * @param sessions The session bundle to use in the creation of the key
       * @param auth_value The auth value to use for the key
       * @param parent The parent key to create the new key under
       * @param group The desired EC Group
       */
      static std::unique_ptr<TPM2::PrivateKey> create_unrestricted_transient(const std::shared_ptr<Context>& ctx,
                                                                             const SessionBundle& sessions,
                                                                             std::span<const uint8_t> auth_value,
                                                                             const TPM2::PrivateKey& parent,
                                                                             const EC_Group& group);

   public:
      std::unique_ptr<Public_Key> public_key() const override;

      /**
       * @returns the public key encoding in ordinary point encoding
       * @sa      EC_PublicKey::set_point_encoding()
       */
      std::vector<uint8_t> public_key_bits() const override;

      /**
       * @returns the public key encoding in TPM2B_PUBLIC format
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      bool supports_operation(PublicKeyOperation op) const override { return op == PublicKeyOperation::Signature; }

      std::unique_ptr<PK_Ops::Signature> create_signature_op(Botan::RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

   protected:
      friend class TPM2::PrivateKey;

      EC_PrivateKey(Object handle,
                    SessionBundle sessions,
                    const TPM2B_PUBLIC* public_blob,
                    std::span<const uint8_t> private_blob = {});

      EC_PrivateKey(Object handle,
                    SessionBundle sessions,
                    std::pair<EC_Group, EC_AffinePoint> public_key,
                    std::span<const uint8_t> private_blob = {});
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
