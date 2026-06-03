/*
 * ML-KEM Composite KEM 
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLKEM_COMP_H_
#define BOTAN_MLKEM_COMP_H_

#include <botan/kyber.h>
#include <botan/ml_dsa.h>
#include <botan/mlkem_comp_parameters.h>
#include <botan/pk_keys.h>
#include <botan/pk_ops_fwd.h>
#include <memory>
#include <span>

namespace Botan {
class BOTAN_PUBLIC_API(3, 0) MLKEM_Composite_PublicKey : public virtual Public_Key {
   public:
      /**
       * Loads a public key.
       *
       * @param key_bits DER encoded public key bits
       */
      BOTAN_FUTURE_EXPLICIT MLKEM_Composite_PublicKey(MLKEM_Composite_Param::id_t id,
                                                      std::span<const uint8_t> key_bits);

      BOTAN_FUTURE_EXPLICIT MLKEM_Composite_PublicKey(const AlgorithmIdentifier& algo_id,
                                                      std::span<const uint8_t> key_bits);

      std::string algo_name() const override { return "MLKEM_Composite"; }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override {
         return this->m_mlkem_pubkey->check_key(rng, strong) && this->m_traditional_pubkey->check_key(rng, strong);
      }

      OID object_identifier() const override;

      /**
       * Return the pessimistic estimated key strength, i.e., the smaller strength of the component keys.
       * This is justified by the assumption that composite algorithms are used in the assumption that
       * one of the component algorithms might be broken.
       *
       * @return the mimium of the components' estimated strengths.
       */
      size_t estimated_strength() const override {
         return std::max(this->m_mlkem_pubkey->estimated_strength(), this->m_traditional_pubkey->estimated_strength());
      }

      /**
       *
       * @return The sum of the component key lengths.
       */
      size_t key_length() const override { return m_mlkem_pubkey->key_length() + m_traditional_pubkey->key_length(); }

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      BOTAN_DEPRECATED("Use raw_public_key_bits()") std::vector<uint8_t> raw_public_key() const;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override {
         return (op == PublicKeyOperation::KeyEncapsulation);
      }

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(
         std::string_view params, std::string_view provider, RandomNumberGenerator* rng_may_be_null) const override;

      MLKEM_Composite_PublicKey(const MLKEM_Composite_PublicKey& other);

      MLKEM_Composite_PublicKey& operator=(const MLKEM_Composite_PublicKey& rhs);

      ~MLKEM_Composite_PublicKey() override = default;

      MLKEM_Composite_PublicKey(const MLKEM_Composite_PublicKey&& other) = delete;
      MLKEM_Composite_PublicKey& operator=(const MLKEM_Composite_PublicKey&& rhs) = delete;

   protected:
      static std::shared_ptr<Public_Key> load_traditional_public_key(const MLKEM_Composite_Param& param,
                                                                     std::span<const uint8_t> key_bits);
      MLKEM_Composite_PublicKey() = default;

      std::shared_ptr<MLKEM_Composite_Param> m_parameters;  // NOLINT(*non-private-member-variable*)
      std::shared_ptr<Kyber_PublicKey> m_mlkem_pubkey;      // NOLINT(*non-private-member-variable*)
      std::shared_ptr<Public_Key> m_traditional_pubkey;     // NOLINT(*non-private-member-variable*)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 0) MLKEM_Composite_PrivateKey final : public virtual MLKEM_Composite_PublicKey,
                                                                public virtual Botan::Private_Key {
   public:
      std::unique_ptr<Public_Key> public_key() const override;

      /**
       * Generates a new key pair
       */
      MLKEM_Composite_PrivateKey(RandomNumberGenerator& rng, MLKEM_Composite_Param param);

      /**
       * Read an encoded private key.
       */
      MLKEM_Composite_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk);

      /**
       * Read an encoded private key.
       */
      MLKEM_Composite_PrivateKey(MLKEM_Composite_Param::id_t id, std::span<const uint8_t> sk);

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      /**
       * Create a signature operation that produces a MLKEM_Composite signature.
       */
      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const override;

      MLKEM_Composite_PrivateKey(const MLKEM_Composite_PrivateKey& other);

      MLKEM_Composite_PrivateKey& operator=(const MLKEM_Composite_PrivateKey& rhs);

      ~MLKEM_Composite_PrivateKey() override = default;

      MLKEM_Composite_PrivateKey(const MLKEM_Composite_PrivateKey&& other) = delete;
      MLKEM_Composite_PrivateKey& operator=(const MLKEM_Composite_PrivateKey&& rhs) = delete;

   private:
      static std::shared_ptr<Private_Key> load_traditional_private_key(const MLKEM_Composite_Param& param,
                                                                       std::span<const uint8_t> key_bits);
      static std::unique_ptr<Private_Key> create_traditional_private_key(RandomNumberGenerator& rng,
                                                                         MLKEM_Composite_Param param);
      void init_pubkey_members();

      secure_vector<uint8_t> encode_traditional_private_key() const;
      friend class MLKEM_Composite_Signature_Operation;
      std::shared_ptr<MLKEM_Composite_Param> m_parameters;
      std::shared_ptr<ML_KEM_PrivateKey> m_mlkem_privkey;
      std::shared_ptr<Private_Key> m_traditional_privkey;
};
}  // namespace Botan

#endif /* BOTAN_MLKEM_COMP_H_ */
