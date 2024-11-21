/*
 * Classic McEliece Key Generation
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_H_
#define BOTAN_CMCE_H_

#include <botan/pk_keys.h>

#include <botan/cmce_parameter_set.h>

namespace Botan {

class Classic_McEliece_PublicKeyInternal;
class Classic_McEliece_PrivateKeyInternal;

/**
 * Classic McEliece is a Code-Based KEM. It is a round 4 candidate in NIST's PQC competition.
 * It is endorsed by the German Federal Office for Information Security (BSI) for its conservative security
 * assumptions and a corresponding draft for an ISO standard has been prepared. Both NIST and ISO parameter
 * sets are implemented here. See https://classic.mceliece.org/ for the specifications and other details.
 *
 * Advantages of Classic McEliece:
 * - Conservative post-quantum security assumptions
 * - Very fast encapsulation
 * - Fast decapsulation
 *
 * Disadvantages of Classic McEliece:
 * - Very large public keys (0.26 MB - 1.36 MB)
 * - Relatively slow key generation
 * - Algorithm is complex and hard to implement side-channel resistant
 */
class BOTAN_PUBLIC_API(3, 7) Classic_McEliece_PublicKey : public virtual Public_Key {
   public:
      /**
       * @brief Load a Classic McEliece public key from bytes.
       *
       * @param alg_id The algorithm identifier
       * @param key_bits The public key bytes
       */
      Classic_McEliece_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
       * @brief Load a Classic McEliece public key from bytes.
       *
       * @param key_bits The public key bytes
       * @param param_set The parameter set
       */
      Classic_McEliece_PublicKey(std::span<const uint8_t> key_bits, Classic_McEliece_Parameter_Set param_set);

      Classic_McEliece_PublicKey(const Classic_McEliece_PublicKey& other);
      Classic_McEliece_PublicKey& operator=(const Classic_McEliece_PublicKey& other);
      Classic_McEliece_PublicKey(Classic_McEliece_PublicKey&&) = default;
      Classic_McEliece_PublicKey& operator=(Classic_McEliece_PublicKey&&) = default;

      ~Classic_McEliece_PublicKey() override = default;

      std::string algo_name() const override { return "ClassicMcEliece"; }

      AlgorithmIdentifier algorithm_identifier() const override;

      OID object_identifier() const override;

      size_t key_length() const override;

      size_t estimated_strength() const override;

      std::vector<uint8_t> public_key_bits() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      bool check_key(RandomNumberGenerator&, bool) const override;

      bool supports_operation(PublicKeyOperation op) const override {
         return (op == PublicKeyOperation::KeyEncapsulation);
      }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(std::string_view params,
                                                                       std::string_view provider) const override;

   protected:
      Classic_McEliece_PublicKey() = default;

   protected:
      std::shared_ptr<Classic_McEliece_PublicKeyInternal>
         m_public;  // NOLINT(misc-non-private-member-variables-in-classes)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 7) Classic_McEliece_PrivateKey final : public virtual Classic_McEliece_PublicKey,
                                                                 public virtual Private_Key {
   public:
      /**
       * @brief Create a new Classic McEliece private key for a specified parameter set.
       *
       * @param rng A random number generator
       * @param param_set The parameter set to use
       */
      Classic_McEliece_PrivateKey(RandomNumberGenerator& rng, Classic_McEliece_Parameter_Set param_set);

      /**
       * @brief Load a Classic McEliece private key from bytes.
       *
       * @param sk The private key bytes
       * @param param_set The parameter set to use
       */
      Classic_McEliece_PrivateKey(std::span<const uint8_t> sk, Classic_McEliece_Parameter_Set param_set);

      /**
       * @brief Load a Classic McEliece private key from bytes.
       *
       * @param alg_id The algorithm identifier
       * @param key_bits The private key bytes
       */
      Classic_McEliece_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      bool check_key(RandomNumberGenerator&, bool) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const override;

   private:
      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> m_private;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif  // BOTAN_CMCE_H_
