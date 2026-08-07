/**
* Abstraction for a combined KEM encryptors and decryptors.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*     2026 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HYBRID_KEM_OPS_H_
#define BOTAN_HYBRID_KEM_OPS_H_

#include <botan/hybrid_kem.h>
#include <botan/pk_algs.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>
#include <botan/internal/pk_ops_impl.h>

#include <utility>
#include <vector>

namespace Botan {

using PairOfSharedSecrets = std::pair<secure_vector<uint8_t>, secure_vector<uint8_t>>;
using PairOfCiphertexts = std::pair<std::vector<uint8_t>, std::vector<uint8_t>>;
using PairOfEncryptors = std::pair<PK_KEM_Encryptor, PK_KEM_Encryptor>;
using PairOfDecryptors = std::pair<PK_KEM_Decryptor, PK_KEM_Decryptor>;

/**
 * @brief Abstract interface for a KEM encryption operation for KEM combiners.
 *
 * Two public keys are used to encapsulate shared secrets. These shared
 * secrets (and maybe the ciphertexts and public keys) are combined using the
 * KEM combiner to derive the final shared secret.
 *
 * Concrete implementations of this class must implement all remaining pure
 * methods including combine_shared_secrets and shared_key_length. They may
 * also override combine_ciphertexts and encapsulated_key_length if the default
 * simple concatenation is not enough.
 */
class KEM_Encryption_with_Combiner : public PK_Ops::KEM_Encryption {
   public:
      KEM_Encryption_with_Combiner(const PairOfPublicKeys& public_keys, std::string_view provider);

      void kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                       std::span<uint8_t> out_shared_key,
                       RandomNumberGenerator& rng,
                       size_t desired_shared_key_len,
                       std::span<const uint8_t> salt) final;

   protected:
      /**
       * Returns the sum of the encapsulated key lengths of the individual encryptors.
       */
      size_t encapsulated_key_length() const override;

      /**
       * @brief Defines how multiple ciphertexts are combined into a single ciphertext.
       *
       * The default implementation concatenates the ciphertexts.
       *
       * @param out_ciphertext The output buffer for the combined ciphertext
       * @param ciphertexts The ciphertexts to combine
       * @param salt The salt. In this default implementation the salt must be empty.
       */
      virtual void combine_ciphertexts(std::span<uint8_t> out_ciphertext,
                                       const PairOfCiphertexts& ciphertexts,
                                       std::span<const uint8_t> salt);

      /**
       * @brief Describes how the shared secrets are combined to derive the final shared secret.
       *
       * @param out_shared_secret the output buffer for the shared secret
       * @param shared_secrets a list of shared secrets corresponding to the public keys
       * @param ciphertexts a list of encapsulated shared secrets
       * @param desired_shared_key_len the desired shared key length
       * @param salt the salt (input of kem_encrypt)
       */
      virtual void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                          const PairOfSharedSecrets& shared_secrets,
                                          const PairOfCiphertexts& ciphertexts,
                                          size_t desired_shared_key_len,
                                          std::span<const uint8_t> salt) = 0;

      PairOfEncryptors& encryptors() { return m_encryptors; }

      const PairOfEncryptors& encryptors() const { return m_encryptors; }

   private:
      PairOfEncryptors m_encryptors;
};

/**
 * @brief Abstract interface for a KEM decryption operation for KEM combiners.
 *
 * Two private keys are used to decapsulate shared secrets from a combined
 * ciphertext. These shared secrets (and maybe the ciphertexts and public keys)
 * are combined using the KEM combiner to derive the final shared secret.
 *
 * Concrete implementations of this class must implement all remaining pure
 * methods including combine_shared_secrets and shared_key_length. They may also
 * override split_ciphertexts and encapsulated_key_length if the default simple
 * split-by-ciphertext-lengths is not enough.
 */
class KEM_Decryption_with_Combiner : public PK_Ops::KEM_Decryption {
   public:
      KEM_Decryption_with_Combiner(const PairOfPrivateKeys& private_keys,
                                   RandomNumberGenerator& rng,
                                   std::string_view provider);

      void kem_decrypt(std::span<uint8_t> out_shared_key,
                       std::span<const uint8_t> encapsulated_key,
                       size_t desired_shared_key_len,
                       std::span<const uint8_t> salt) final;

   protected:
      /**
       * Returns the sum of the encapsulated key lengths of the individual decryptors.
       */
      size_t encapsulated_key_length() const override;

      /**
       * @brief Defines how the individual ciphertexts are extracted from the combined ciphertext.
       *
       * The default implementation splits concatenated ciphertexts.
       * @param concat_ciphertext The combined ciphertext
       * @returns The individual ciphertexts
       */
      virtual PairOfCiphertexts split_ciphertexts(std::span<const uint8_t> concat_ciphertext);

      /**
       * @brief Describes how the shared secrets are combined to derive the final shared secret.
       *
       * @param out_shared_secret the output buffer for the shared secret
       * @param shared_secrets a list of shared secrets corresponding to the public keys
       * @param ciphertexts the list of encapsulated shared secrets
       * @param desired_shared_key_len the desired shared key length
       * @param salt the salt (input of kem_decrypt)
       */
      virtual void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                          const PairOfSharedSecrets& shared_secrets,
                                          const PairOfCiphertexts& ciphertexts,
                                          size_t desired_shared_key_len,
                                          std::span<const uint8_t> salt) = 0;

      PairOfDecryptors& decryptors() { return m_decryptors; }

      const PairOfDecryptors& decryptors() const { return m_decryptors; }

   private:
      PairOfDecryptors m_decryptors;
};

}  // namespace Botan

#endif  // BOTAN_HYBRID_KEM_OPS_H_
