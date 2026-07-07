/**
* Abstraction for a combined KEM public and private key.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*     2026 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HYBRID_KEM_H_
#define BOTAN_HYBRID_KEM_H_

#include <botan/pk_algs.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>

#include <memory>
#include <utility>

namespace Botan {

using PairOfPublicKeys = std::pair<std::unique_ptr<Public_Key>, std::unique_ptr<Public_Key>>;
using PairOfPrivateKeys = std::pair<std::unique_ptr<Private_Key>, std::unique_ptr<Private_Key>>;

/**
 * @brief Abstraction for a combined KEM public key.
 *
 * Two KEM public keys are combined into a single KEM public key. This is typically used
 * to build hybrids of a traditional and a post-quantum algorithm. This class does not
 * make any assumptions about which underlying key is used first or second.
 *
 * Derived classes must implement the remaining abstract methods to provide the encryption
 * operation, e.g. by specifying how encryption results are combined to the ciphertext and
 * how a KEM combiner is applied to derive the shared secret using the individual shared
 * secrets, ciphertexts, and other context information. Additionally, derived classes may
 * override the serialization and deserialization of the combined public key or add specific
 * algorithm identifiers.
 */
class BOTAN_TEST_API Hybrid_KEM_PublicKey : public virtual Public_Key {
   public:
      /**
       * @brief Constructor for a pair of KEM public keys.
       *
       * Note that this constructor automatically wraps key-exchange (KEX) keys
       * into a KEX_to_KEM_Adapter_PublicKey to make them compatible with this
       * hybrid wrapper.
       *
       * @param public_keys Pair of public keys to combine
       * @throws Botan::Invalid_Argument if any of the keys is a nullptr or does
       *         not support key encapsulation or key agreement
       */
      explicit Hybrid_KEM_PublicKey(PairOfPublicKeys public_keys);

      Hybrid_KEM_PublicKey(Hybrid_KEM_PublicKey&&) = default;
      Hybrid_KEM_PublicKey(const Hybrid_KEM_PublicKey&) = delete;
      Hybrid_KEM_PublicKey& operator=(Hybrid_KEM_PublicKey&&) = default;
      Hybrid_KEM_PublicKey& operator=(const Hybrid_KEM_PublicKey&) = delete;
      ~Hybrid_KEM_PublicKey() override = default;

      size_t estimated_strength() const override;
      size_t key_length() const override;
      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      /**
       * @brief Return the public key bits of this hybrid key as the concatenated
       *        bytes of the individual public keys (without encoding).
       *
       * @return the public key bytes
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      /**
       * @brief Return the public key bits of this hybrid key as the concatenated
       *        bytes of the individual public keys.
       *
       * @return the public key bytes
       */
      std::vector<uint8_t> public_key_bits() const override;

      bool supports_operation(PublicKeyOperation op) const override;

      /// @returns the public keys combined in this hybrid key
      const PairOfPublicKeys& public_keys() const { return m_pks; }

   protected:
      // Default constructor used for virtual inheritance to prevent, that the derived class
      // calls the constructor twice.
      Hybrid_KEM_PublicKey() = default;

   private:
      PairOfPublicKeys m_pks;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * @brief Abstraction for a combined KEM private key.
 *
 * Two private keys are combined into a single KEM private key. Derived classes
 * must implement the abstract methods to provide the decryption operation, e.g. by
 * specifying how a KEM combiner is applied to derive the shared secret using the
 * individual shared secrets, ciphertexts, and other context information.
 */
class BOTAN_TEST_API Hybrid_KEM_PrivateKey : virtual public Private_Key {
   public:
      Hybrid_KEM_PrivateKey(const Hybrid_KEM_PrivateKey&) = delete;
      Hybrid_KEM_PrivateKey& operator=(const Hybrid_KEM_PrivateKey&) = delete;

      Hybrid_KEM_PrivateKey(Hybrid_KEM_PrivateKey&&) = default;
      Hybrid_KEM_PrivateKey& operator=(Hybrid_KEM_PrivateKey&&) = default;

      ~Hybrid_KEM_PrivateKey() override = default;

      /**
       * @brief Constructor for a pair of KEM private keys.
       *
       * Note that this constructor automatically wraps key-exchange (KEX) keys
       * into a KEX_to_KEM_Adapter_PrivateKey to make them compatible with this
       * hybrid wrapper.
       *
       * @param private_keys Pair of private keys to combine
       * @throws Botan::Invalid_Argument if any of the keys is a nullptr or does
       *         not support key encapsulation or key agreement
       */
      explicit Hybrid_KEM_PrivateKey(PairOfPrivateKeys private_keys);

      /// Disabled by default
      secure_vector<uint8_t> private_key_bits() const override;

      /// @returns the private keys combined in this hybrid key
      const PairOfPrivateKeys& private_keys() const { return m_sks; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

   protected:
      static PairOfPublicKeys extract_public_keys(const PairOfPrivateKeys& private_keys);

   private:
      PairOfPrivateKeys m_sks;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
