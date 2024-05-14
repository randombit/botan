/**
* Abstraction for a combined KEM public and private key.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HYBRID_KEM_H_
#define BOTAN_HYBRID_KEM_H_

#include <botan/pk_algs.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>

#include <memory>
#include <vector>

namespace Botan {

/**
 * @brief Abstraction for a combined KEM public key.
 *
 * Two or more KEM public keys are combined into a single KEM public key. Derived classes
 * must implement the abstract methods to provide the encryption operation, e.g. by
 * specifying how encryption results are combined to the ciphertext and how a KEM combiner
 * is applied to derive the shared secret using the individual shared secrets, ciphertexts,
 * and other context information.
 */
class BOTAN_TEST_API Hybrid_PublicKey : public virtual Public_Key {
   public:
      /**
       * @brief Constructor for a list of multiple KEM public keys.
       *
       * To use KEX algorithms use the KEX_to_KEM_Adapter_PublicKey.
       * @param public_keys List of public keys to combine
       */
      explicit Hybrid_PublicKey(std::vector<std::unique_ptr<Public_Key>> public_keys);

      Hybrid_PublicKey(Hybrid_PublicKey&&) = default;
      Hybrid_PublicKey(const Hybrid_PublicKey&) = delete;
      Hybrid_PublicKey& operator=(Hybrid_PublicKey&&) = default;
      Hybrid_PublicKey& operator=(const Hybrid_PublicKey&) = delete;
      ~Hybrid_PublicKey() override = default;

      size_t estimated_strength() const override { return m_estimated_strength; }

      size_t key_length() const override { return m_key_length; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      /**
       * @brief Return the public key bits of this hybrid key as the concatenated
       *        bytes of the individual public keys (without encoding).
       *
       * @return the public key bytes
       */
      std::vector<uint8_t> public_key_bits() const override { return raw_public_key_bits(); }

      bool supports_operation(PublicKeyOperation op) const override;

      /// @returns the public keys combined in this hybrid key
      const std::vector<std::unique_ptr<Public_Key>>& public_keys() const { return m_pks; }

   protected:
      // Default constructor used for virtual inheritance to prevent, that the derived class
      // calls the constructor twice.
      Hybrid_PublicKey() = default;

      /**
       * @brief Helper function for generate_another. Generate a new private key for each
       *        public key in this hybrid key.
       */
      std::vector<std::unique_ptr<Private_Key>> generate_other_sks_from_pks(RandomNumberGenerator& rng) const;

   private:
      std::vector<std::unique_ptr<Public_Key>> m_pks;

      size_t m_key_length;
      size_t m_estimated_strength;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * @brief Abstraction for a combined KEM private key.
 *
 * Two or more KEM private keys are combined into a single KEM private key. Derived classes
 * must implement the abstract methods to provide the decryption operation, e.g. by
 * specifying how a KEM combiner is applied to derive the shared secret using the
 * individual shared secrets, ciphertexts, and other context information.
 */
class BOTAN_TEST_API Hybrid_PrivateKey : virtual public Private_Key {
   public:
      Hybrid_PrivateKey(const Hybrid_PrivateKey&) = delete;
      Hybrid_PrivateKey& operator=(const Hybrid_PrivateKey&) = delete;

      Hybrid_PrivateKey(Hybrid_PrivateKey&&) = default;
      Hybrid_PrivateKey& operator=(Hybrid_PrivateKey&&) = default;

      ~Hybrid_PrivateKey() override = default;

      /**
       * @brief Constructor for a list of multiple KEM private keys.
       *
       * To use KEX algorithms use the KEX_to_KEM_Adapter_PrivateKey.
       * @param private_keys List of private keys to combine
       */
      Hybrid_PrivateKey(std::vector<std::unique_ptr<Private_Key>> private_keys);

      /// Disabled by default
      secure_vector<uint8_t> private_key_bits() const override;

      /// @returns the private keys combined in this hybrid key
      const std::vector<std::unique_ptr<Private_Key>>& private_keys() const { return m_sks; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

   protected:
      static std::vector<std::unique_ptr<Public_Key>> extract_public_keys(
         const std::vector<std::unique_ptr<Private_Key>>& private_keys);

   private:
      std::vector<std::unique_ptr<Private_Key>> m_sks;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
