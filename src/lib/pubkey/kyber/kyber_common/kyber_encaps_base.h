/*
 * Key encapsulation base operations for Kyber
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_KEY_ENCAPSULATION_BASE_H_
#define BOTAN_KYBER_KEY_ENCAPSULATION_BASE_H_

#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_keys.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

class Kyber_KEM_Operation_Base {
   protected:
      Kyber_KEM_Operation_Base(const Kyber_PublicKeyInternal& pk) :
            m_At(Kyber_Algos::sample_matrix(pk.rho(), true /* transposed */, pk.mode())) {}

      const KyberPolyMat& precomputed_matrix_At() const { return m_At; }

   private:
      // The public key's matrix is pre-computed to avoid redundant work when
      // encapsulating multiple keys. This matrix is needed for encapsulation as
      // well as for the FO transform in the decapsulation.
      KyberPolyMat m_At;
};

class Kyber_KEM_Encryptor_Base : public PK_Ops::KEM_Encryption_with_KDF,
                                 protected Kyber_KEM_Operation_Base {
   public:
      size_t raw_kem_shared_key_length() const override { return mode().shared_key_bytes(); }

      size_t encapsulated_key_length() const override { return mode().ciphertext_bytes(); }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> out_shared_key,
                           RandomNumberGenerator& rng) final {
         encapsulate(StrongSpan<KyberCompressedCiphertext>(out_encapsulated_key),
                     StrongSpan<KyberSharedSecret>(out_shared_key),
                     rng);
      }

   protected:
      Kyber_KEM_Encryptor_Base(std::string_view kdf, const Kyber_PublicKeyInternal& pk) :
            PK_Ops::KEM_Encryption_with_KDF(kdf), Kyber_KEM_Operation_Base(pk) {}

      virtual void encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                               StrongSpan<KyberSharedSecret> out_shared_key,
                               RandomNumberGenerator& rng) = 0;

      virtual const KyberConstants& mode() const = 0;
};

class Kyber_KEM_Decryptor_Base : public PK_Ops::KEM_Decryption_with_KDF,
                                 protected Kyber_KEM_Operation_Base {
   public:
      size_t raw_kem_shared_key_length() const override { return mode().shared_key_bytes(); }

      size_t encapsulated_key_length() const override { return mode().ciphertext_bytes(); }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encapsulated_key) final {
         decapsulate(StrongSpan<KyberSharedSecret>(out_shared_key),
                     StrongSpan<const KyberCompressedCiphertext>(encapsulated_key));
      }

   protected:
      Kyber_KEM_Decryptor_Base(std::string_view kdf, const Kyber_PublicKeyInternal& pk) :
            PK_Ops::KEM_Decryption_with_KDF(kdf), Kyber_KEM_Operation_Base(pk) {}

      virtual void decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                               StrongSpan<const KyberCompressedCiphertext> encapsulated_key) = 0;

      virtual const KyberConstants& mode() const = 0;
};

}  // namespace Botan

#endif
