/**
* Abstraction for a combined KEM encryptors and decryptors.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HYBRID_KEM_OPS_H_
#define BOTAN_HYBRID_KEM_OPS_H_

#include <botan/pk_algs.h>
#include <botan/pubkey.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

#include <memory>
#include <vector>

namespace Botan {

/**
 * @brief Abstract interface for a KEM encryption operation for KEM combiners.
 *
 * Multiple public keys are used to encapsulate shared secrets. These shared
 * secrets (and maybe the ciphertexts and public keys) are combined using the
 * KEM combiner to derive the final shared secret.
 *
 */
class KEM_Encryption_with_Combiner : public PK_Ops::KEM_Encryption {
   public:
      KEM_Encryption_with_Combiner(const std::vector<std::unique_ptr<Public_Key>>& public_keys,
                                   std::string_view provider);

      void kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                       std::span<uint8_t> out_shared_key,
                       RandomNumberGenerator& rng,
                       size_t desired_shared_key_len,
                       std::span<const uint8_t> salt) final;

      /// The default implementation returns the sum of the encapsulated key lengths of the underlying KEMs.
      size_t encapsulated_key_length() const override { return m_encapsulated_key_length; }

   protected:
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
                                       const std::vector<std::vector<uint8_t>>& ciphertexts,
                                       std::span<const uint8_t> salt);

      /**
       * @brief Describes how the shared secrets are combined to derive the final shared secret.
       *
       * @param out_shared_secret the output buffer for the shared secret
       * @param shared_secrets a list of shared secrets coreesponding to the public keys
       * @param ciphertexts a list of encapsulated shared secrets
       * @param desired_shared_key_len the desired shared key length
       * @param salt the salt (input of kem_encrypt)
       */
      virtual void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                          const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                          const std::vector<std::vector<uint8_t>>& ciphertexts,
                                          size_t desired_shared_key_len,
                                          std::span<const uint8_t> salt) = 0;

      std::vector<PK_KEM_Encryptor>& encryptors() { return m_encryptors; }

      const std::vector<PK_KEM_Encryptor>& encryptors() const { return m_encryptors; }

   private:
      std::vector<PK_KEM_Encryptor> m_encryptors;
      size_t m_encapsulated_key_length;
};

/**
 * @brief Abstract interface for a KEM decryption operation for KEM combiners.
 *
 * Multiple private keys are used to decapsulate shared secrets from a combined
 * ciphertext (concatenated in most cases). These shared
 * secrets (and maybe the ciphertexts and public keys) are combined using the
 * KEM combiner to derive the final shared secret.
 */
class KEM_Decryption_with_Combiner : public PK_Ops::KEM_Decryption {
   public:
      KEM_Decryption_with_Combiner(const std::vector<std::unique_ptr<Private_Key>>& private_keys,
                                   RandomNumberGenerator& rng,
                                   std::string_view provider);

      void kem_decrypt(std::span<uint8_t> out_shared_key,
                       std::span<const uint8_t> encapsulated_key,
                       size_t desired_shared_key_len,
                       std::span<const uint8_t> salt) final;

      /// The default implementation returns the sum of the encapsulated key lengths of the underlying KEMs.
      size_t encapsulated_key_length() const override { return m_encapsulated_key_length; }

   protected:
      /**
       * @brief Defines how the individual ciphertexts are extracted from the combined ciphertext.
       *
       * The default implementation splits concatenated ciphertexts.
       * @param concat_ciphertext The combined ciphertext
       * @returns The individual ciphertexts
       */
      virtual std::vector<std::vector<uint8_t>> split_ciphertexts(std::span<const uint8_t> concat_ciphertext);

      /**
       * @brief Describes how the shared secrets are combined to derive the final shared secret.
       *
       * @param out_shared_secret the output buffer for the shared secret
       * @param shared_secrets a list of shared secrets coreesponding to the public keys
       * @param ciphertexts the list of encapsulated shared secrets
       * @param desired_shared_key_len the desired shared key length
       * @param salt the salt (input of kem_decrypt)
       */
      virtual void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                          const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                          const std::vector<std::vector<uint8_t>>& ciphertexts,
                                          size_t desired_shared_key_len,
                                          std::span<const uint8_t> salt) = 0;

      std::vector<PK_KEM_Decryptor>& decryptors() { return m_decryptors; }

      const std::vector<PK_KEM_Decryptor>& decryptors() const { return m_decryptors; }

   private:
      std::vector<PK_KEM_Decryptor> m_decryptors;
      size_t m_encapsulated_key_length;
};

}  // namespace Botan

#endif  // BOTAN_HYBRID_KEM_OPS_H_
