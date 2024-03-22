/*
 * Crystals Kyber key encapsulation mechanism
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_R3_ENCAPSULATION_H_
#define BOTAN_KYBER_R3_ENCAPSULATION_H_

#include <botan/rng.h>

#include <botan/internal/kyber_encaps_base.h>
#include <botan/internal/kyber_keys.h>

namespace Botan {

class Kyber_KEM_Encryptor final : public Kyber_KEM_Encryptor_Base {
   public:
      Kyber_KEM_Encryptor(std::shared_ptr<const Kyber_PublicKeyInternal> key, std::string_view kdf) :
            Kyber_KEM_Encryptor_Base(kdf), m_public_key(std::move(key)) {}

   protected:
      void encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                       StrongSpan<KyberSharedSecret> out_shared_key,
                       RandomNumberGenerator& rng) override;

      const KyberConstants& mode() const override { return m_public_key->mode(); }

   private:
      std::shared_ptr<const Kyber_PublicKeyInternal> m_public_key;
};

class Kyber_KEM_Decryptor final : public Kyber_KEM_Decryptor_Base {
   public:
      Kyber_KEM_Decryptor(std::shared_ptr<const Kyber_PrivateKeyInternal> private_key,
                          std::shared_ptr<const Kyber_PublicKeyInternal> public_key,
                          std::string_view kdf) :
            Kyber_KEM_Decryptor_Base(kdf), m_public_key(std::move(public_key)), m_private_key(std::move(private_key)) {}

   protected:
      void decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                       StrongSpan<const KyberCompressedCiphertext> encapsulated_key) override;

      const KyberConstants& mode() const override { return m_private_key->mode(); }

   private:
      std::shared_ptr<const Kyber_PublicKeyInternal> m_public_key;
      std::shared_ptr<const Kyber_PrivateKeyInternal> m_private_key;
};

}  // namespace Botan

#endif
