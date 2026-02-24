/*
 * ML-DSA Composite Signature Schemes
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLDSA_COMP_H_
#define BOTAN_MLDSA_COMP_H_

#include <botan/dilithium.h>
#include <botan/ml_dsa.h>
#include <botan/mldsa_comp_parameters.h>
#include <botan/pk_keys.h>
#include <memory>
#include <span>

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) MLDSA_Composite_PublicKey : public virtual Public_Key {
   public:
      /**
       * Loads a public key.
       *
       * @param key_bits DER encoded public key bits
       */
      BOTAN_FUTURE_EXPLICIT MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id,
                                                      std::span<const uint8_t> key_bits);

      BOTAN_FUTURE_EXPLICIT MLDSA_Composite_PublicKey(const AlgorithmIdentifier& algo_id,
                                                      std::span<const uint8_t> key_bits);

      std::string algo_name() const override { return "MLDSA_Composite"; }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override {
         return this->m_mldsa_pubkey->check_key(rng, strong) && this->m_traditional_pubkey->check_key(rng, strong);
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
         return std::min(this->m_mldsa_pubkey->estimated_strength(), this->m_traditional_pubkey->estimated_strength());
      }

      /**
       *
       * @return The sum of the component key lengths.
       */
      size_t key_length() const override { return m_mldsa_pubkey->key_length() + m_traditional_pubkey->key_length(); }

      std::vector<uint8_t> raw_public_key_bits() const override;

      std::vector<uint8_t> public_key_bits() const override;

      BOTAN_DEPRECATED("Use raw_public_key_bits()") std::vector<uint8_t> raw_public_key() const;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                        std::string_view provider) const override;

      MLDSA_Composite_PublicKey(const MLDSA_Composite_PublicKey& other);

      MLDSA_Composite_PublicKey& operator=(const MLDSA_Composite_PublicKey& rhs);

      ~MLDSA_Composite_PublicKey() override = default;

      MLDSA_Composite_PublicKey(const MLDSA_Composite_PublicKey&& other) = delete;
      MLDSA_Composite_PublicKey& operator=(const MLDSA_Composite_PublicKey&& rhs) = delete;

   protected:
      static std::shared_ptr<Public_Key> load_traditional_public_key(const MLDSA_Composite_Param& param,
                                                                     std::span<const uint8_t> key_bits);
      MLDSA_Composite_PublicKey() = default;

      std::shared_ptr<MLDSA_Composite_Param> m_parameters;  // NOLINT(*non-private-member-variable*)
      std::shared_ptr<Dilithium_PublicKey> m_mldsa_pubkey;  // NOLINT(*non-private-member-variable*)
      std::shared_ptr<Public_Key> m_traditional_pubkey;     // NOLINT(*non-private-member-variable*)
};

class BOTAN_PUBLIC_API(3, 0) MLDSA_Composite_PrivateKey final : public virtual MLDSA_Composite_PublicKey,
                                                                public virtual Botan::Private_Key {
   public:
      std::unique_ptr<Public_Key> public_key() const override;

      /**
       * Generates a new key pair
       */
      MLDSA_Composite_PrivateKey(RandomNumberGenerator& rng, MLDSA_Composite_Param param);

      /**
       * Read an encoded private key.
       */
      MLDSA_Composite_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk);

      MLDSA_Composite_PrivateKey(MLDSA_Composite_Param::id_t id, std::span<const uint8_t> sk);

      /**
       * Read an encoded private key given the composite @p param.
       */
      //MLDSA_Composite_PrivateKey(std::span<const uint8_t> sk, MLDSA_Composite_Param param);

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      /**
       * Create a signature operation that produces a MLDSA_Composite signature.
       */
      std::unique_ptr<PK_Ops::Signature> create_signature_op(RandomNumberGenerator& rng,
                                                             std::string_view params,
                                                             std::string_view provider) const override;

      MLDSA_Composite_PrivateKey(const MLDSA_Composite_PrivateKey& other);

      MLDSA_Composite_PrivateKey& operator=(const MLDSA_Composite_PrivateKey& rhs);

      ~MLDSA_Composite_PrivateKey() override = default;

      MLDSA_Composite_PrivateKey(const MLDSA_Composite_PrivateKey&& other) = delete;
      MLDSA_Composite_PrivateKey& operator=(const MLDSA_Composite_PrivateKey&& rhs) = delete;

   private:
      static std::shared_ptr<Private_Key> load_traditional_private_key(const MLDSA_Composite_Param& param,
                                                                       std::span<const uint8_t> key_bits);
      static std::unique_ptr<Private_Key> create_traditional_private_key(RandomNumberGenerator& rng,
                                                                         MLDSA_Composite_Param param);
      void init_pubkey_members();

      secure_vector<uint8_t> encode_traditional_private_key() const;
      friend class MLDSA_Composite_Signature_Operation;
      std::shared_ptr<MLDSA_Composite_Param> m_parameters;
      std::shared_ptr<ML_DSA_PrivateKey> m_mldsa_privkey;
      std::shared_ptr<Private_Key> m_traditional_privkey;
};

}  // namespace Botan
#endif /* BOTAN_MLDSA_COMP_H_ */
