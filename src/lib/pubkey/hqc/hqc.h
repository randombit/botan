/*
 * HQC key encapsulation mechanism
 *
 * Wraps the Rust implementation in the crate rust-hqc via its C API.
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_HQC_H_
#define BOTAN_HQC_H_

#include <botan/hqc_mode.h>
#include <botan/pk_keys.h>

#include <memory>
#include <span>
#include <vector>

namespace Botan {

class HQC_PublicKeyInternal;
class HQC_PrivateKeyInternal;

/**
 * HQC (Hamming Quasi-Cyclic) is a code-based post-quantum secure KEM that was
 * selected by NIST in March 2025 for standardization as a backup to ML-KEM.
 * This implementation follows the HQC specification of 2025-08-22.
 *
 * The cryptographic core is implemented in Rust (crate rust-hqc) and linked as
 * a static library; this module is not built by default.
 */
class BOTAN_PUBLIC_API(3, 14) HQC_PublicKey : public virtual Public_Key {
   public:
      HQC_PublicKey(std::span<const uint8_t> pub_key, HQC_Mode mode);

      HQC_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      HQC_PublicKey(const HQC_PublicKey& other) = default;
      HQC_PublicKey& operator=(const HQC_PublicKey& other) = default;
      HQC_PublicKey(HQC_PublicKey&&) = default;
      HQC_PublicKey& operator=(HQC_PublicKey&&) = default;

      ~HQC_PublicKey() override = default;

      std::string algo_name() const override { return "HQC"; }

      AlgorithmIdentifier algorithm_identifier() const override;

      OID object_identifier() const override;

      size_t key_length() const override;

      size_t estimated_strength() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      bool supports_operation(PublicKeyOperation op) const override {
         return (op == PublicKeyOperation::KeyEncapsulation);
      }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      std::unique_ptr<PK_Ops::KEM_Encryption> _create_kem_encryption_op(
         const PK_KEM_Options_Reader& options) const override;

   protected:
      HQC_PublicKey() = default;

   protected:
      std::shared_ptr<const HQC_PublicKeyInternal> m_public;  // NOLINT(*-non-private-member-variable*)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 14) HQC_PrivateKey final : public virtual HQC_PublicKey,
                                                     public virtual Private_Key {
   public:
      HQC_PrivateKey(RandomNumberGenerator& rng, HQC_Mode mode);

      HQC_PrivateKey(std::span<const uint8_t> sk, HQC_Mode mode);

      HQC_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> _create_kem_decryption_op(
         RandomNumberGenerator& rng, const PK_KEM_Options_Reader& options) const override;

   private:
      std::shared_ptr<const HQC_PrivateKeyInternal> m_private;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
