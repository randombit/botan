/*
 * Module-Lattice Key Encapsulation Mechanism (ML-KEM)
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ML_KEM_IMPL_H_
#define BOTAN_ML_KEM_IMPL_H_

#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/xof.h>

#include <botan/internal/kyber_encaps_base.h>
#include <botan/internal/kyber_keys.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>
#include <botan/internal/loadstor.h>

namespace Botan {

class ML_KEM_Encryptor final : public Kyber_KEM_Encryptor_Base {
   public:
      ML_KEM_Encryptor(std::shared_ptr<const Kyber_PublicKeyInternal> key, std::string_view kdf) :
            Kyber_KEM_Encryptor_Base(kdf, *key), m_public_key(std::move(key)) {}

   protected:
      void encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                       StrongSpan<KyberSharedSecret> out_shared_key,
                       RandomNumberGenerator& rng) override;

   private:
      std::shared_ptr<const Kyber_PublicKeyInternal> m_public_key;
};

class ML_KEM_Decryptor final : public Kyber_KEM_Decryptor_Base {
   public:
      ML_KEM_Decryptor(std::shared_ptr<const Kyber_PrivateKeyInternal> private_key,
                       std::shared_ptr<const Kyber_PublicKeyInternal> public_key,
                       std::string_view kdf) :
            Kyber_KEM_Decryptor_Base(kdf, *public_key),
            m_public_key(std::move(public_key)),
            m_private_key(std::move(private_key)) {}

   protected:
      void decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                       StrongSpan<const KyberCompressedCiphertext> encapsulated_key) override;

   private:
      std::shared_ptr<const Kyber_PublicKeyInternal> m_public_key;
      std::shared_ptr<const Kyber_PrivateKeyInternal> m_private_key;
};

class ML_KEM_Symmetric_Primitives final : public Kyber_Symmetric_Primitives {
   protected:
      std::optional<std::array<uint8_t, 1>> seed_expansion_domain_separator(const KyberConstants& mode) const override {
         // NIST FIPS 203, Algorithm 13 (K-PKE.KeyGen)
         //    Byte 33 of the input to G is the module dimension k from {2,3,4}.
         //    This is included to establish domain separation between the three
         //    parameter sets
         return std::array{mode.k()};
      }

      std::unique_ptr<HashFunction> create_G() const override { return HashFunction::create_or_throw("SHA-3(512)"); }

      std::unique_ptr<HashFunction> create_H() const override { return HashFunction::create_or_throw("SHA-3(256)"); }

      std::unique_ptr<HashFunction> create_J() const override {
         return HashFunction::create_or_throw("SHAKE-256(256)");
      }

      std::unique_ptr<HashFunction> create_KDF() const override {
         throw Invalid_State("ML-KEM does not support KDF()");
      }

      std::unique_ptr<Botan::XOF> create_PRF(std::span<const uint8_t> seed, const uint8_t nonce) const override {
         auto xof = Botan::XOF::create_or_throw("SHAKE-256");
         init_PRF(*xof, seed, nonce);
         return xof;
      }

      void init_PRF(Botan::XOF& xof, std::span<const uint8_t> seed, const uint8_t nonce) const override {
         xof.clear();
         xof.update(seed);
         xof.update(store_be(nonce));
      }

      std::unique_ptr<Botan::XOF> create_XOF(std::span<const uint8_t> seed,
                                             std::tuple<uint8_t, uint8_t> matrix_position) const override {
         auto xof = Botan::XOF::create_or_throw("SHAKE-128");
         init_XOF(*xof, seed, matrix_position);
         return xof;
      }

      void init_XOF(Botan::XOF& xof,
                    std::span<const uint8_t> seed,
                    std::tuple<uint8_t, uint8_t> matrix_position) const override {
         xof.clear();
         xof.update(seed);
         xof.update(store_be(make_uint16(std::get<0>(matrix_position), std::get<1>(matrix_position))));
      }
};

}  // namespace Botan

#endif
