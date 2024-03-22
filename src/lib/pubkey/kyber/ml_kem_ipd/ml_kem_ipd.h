/*
 * Module-Lattice Key Encapsulation Mechanism (ML-KEM), Initial Public Draft
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ML_KEM_INITIAL_PUBLIC_DRAFT_H_
#define BOTAN_ML_KEM_INITIAL_PUBLIC_DRAFT_H_

#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/xof.h>

#include <botan/internal/kyber_encaps_base.h>
#include <botan/internal/kyber_keys.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

class ML_KEM_IPD_Encryptor final : public Kyber_KEM_Encryptor_Base {
   public:
      ML_KEM_IPD_Encryptor(std::shared_ptr<const Kyber_PublicKeyInternal> key, std::string_view kdf) :
            Kyber_KEM_Encryptor_Base(kdf), m_public_key(std::move(key)) {}

   protected:
      void encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                       StrongSpan<KyberSharedSecret> out_shared_key,
                       RandomNumberGenerator& rng) override;

      const KyberConstants& mode() const override { return m_public_key->mode(); }

   private:
      std::shared_ptr<const Kyber_PublicKeyInternal> m_public_key;
};

class ML_KEM_IPD_Decryptor final : public Kyber_KEM_Decryptor_Base {
   public:
      ML_KEM_IPD_Decryptor(std::shared_ptr<const Kyber_PrivateKeyInternal> private_key,
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

class ML_KEM_IPD_Symmetric_Primitives : public Kyber_Symmetric_Primitives {
   public:
      ML_KEM_IPD_Symmetric_Primitives() :
            m_sha3_512(HashFunction::create_or_throw("SHA-3(512)")),
            m_sha3_256(HashFunction::create_or_throw("SHA-3(256)")),
            m_shake256_256(HashFunction::create_or_throw("SHAKE-256(256)")),
            m_shake128(Botan::XOF::create_or_throw("SHAKE-128")),
            m_shake256(Botan::XOF::create_or_throw("SHAKE-256")) {}

   protected:
      HashFunction& get_G() const override { return *m_sha3_512; }

      HashFunction& get_H() const override { return *m_sha3_256; }

      HashFunction& get_J() const override { return *m_shake256_256; }

      HashFunction& get_KDF() const override { throw Invalid_State("ML-KEM IPD does not support KDF()"); }

      Botan::XOF& get_PRF(std::span<const uint8_t> seed, const uint8_t nonce) const override {
         m_shake256->clear();
         m_shake256->update(seed);
         m_shake256->update(store_be(nonce));
         return *m_shake256;
      }

      std::unique_ptr<Botan::XOF> get_XOF(std::span<const uint8_t> seed,
                                          std::tuple<uint8_t, uint8_t> matrix_position) const override {
         auto xof = m_shake128->new_object();
         xof->update(seed);
         xof->update(store_be(make_uint16(std::get<0>(matrix_position), std::get<1>(matrix_position))));
         return xof;
      }

   private:
      std::unique_ptr<HashFunction> m_sha3_512;
      std::unique_ptr<HashFunction> m_sha3_256;
      std::unique_ptr<HashFunction> m_shake256_256;
      std::unique_ptr<Botan::XOF> m_shake128;
      std::unique_ptr<Botan::XOF> m_shake256;
};

}  // namespace Botan

#endif
