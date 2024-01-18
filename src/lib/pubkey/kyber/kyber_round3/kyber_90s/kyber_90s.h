/*
 * Symmetric primitives for Kyber (90s mode)
 * (C) 2022 Jack Lloyd
 * (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_90S_H_
#define BOTAN_KYBER_90S_H_

#include <botan/hash.h>
#include <botan/internal/aes_crystals_xof.h>

#include <botan/internal/kyber_symmetric_primitives.h>

#include <array>
#include <memory>

namespace Botan {

class Kyber_90s_Symmetric_Primitives : public Kyber_Symmetric_Primitives {
   public:
      Kyber_90s_Symmetric_Primitives() :
            m_sha512(HashFunction::create_or_throw("SHA-512")),
            m_sha256(HashFunction::create_or_throw("SHA-256")),
            m_aes256_xof(std::make_unique<AES_256_CTR_XOF>()) {}

   protected:
      HashFunction& get_G() const override { return *m_sha512; }

      HashFunction& get_H() const override { return *m_sha256; }

      HashFunction& get_KDF() const override { return *m_sha256; }

      Botan::XOF& get_PRF(std::span<const uint8_t> seed, const uint8_t nonce) const override {
         m_aes256_xof->clear();
         const std::array<uint8_t, 12> nonce_buffer{nonce, 0};
         m_aes256_xof->start(nonce_buffer, seed);
         return *m_aes256_xof;
      }

      std::unique_ptr<Botan::XOF> get_XOF(std::span<const uint8_t> seed,
                                          std::tuple<uint8_t, uint8_t> mpos) const override {
         auto xof = m_aes256_xof->new_object();
         const std::array<uint8_t, 12> iv{std::get<0>(mpos), std::get<1>(mpos), 0};
         xof->start(iv, seed);
         return xof;
      }

   private:
      std::unique_ptr<HashFunction> m_sha512;
      std::unique_ptr<HashFunction> m_sha256;
      std::unique_ptr<AES_256_CTR_XOF> m_aes256_xof;
};

}  // namespace Botan

#endif
