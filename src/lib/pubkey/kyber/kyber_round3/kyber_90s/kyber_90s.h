/*
 * Symmetric primitives for Kyber (90s mode)
 * (C) 2022-2024 Jack Lloyd
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

class Kyber_90s_Symmetric_Primitives final : public Kyber_Symmetric_Primitives {
   public:
      Kyber_90s_Symmetric_Primitives() :
            m_sha512(HashFunction::create_or_throw("SHA-512")),
            m_sha256(HashFunction::create_or_throw("SHA-256")),
            m_aes256_xof(std::make_unique<AES_256_CTR_XOF>()) {}

   protected:
      std::optional<std::array<uint8_t, 1>> seed_expansion_domain_separator(const KyberConstants&) const override {
         return {};
      }

      HashFunction& get_G() const override { return *m_sha512; }

      HashFunction& get_H() const override { return *m_sha256; }

      HashFunction& get_J() const override { throw Invalid_State("Kyber-R3 in 90s mode does not support J()"); }

      HashFunction& get_KDF() const override { return *m_sha256; }

      Botan::XOF& get_PRF(std::span<const uint8_t> seed, const uint8_t nonce) const override {
         m_aes256_xof->clear();
         const std::array<uint8_t, 12> nonce_buffer{nonce, 0};
         m_aes256_xof->start(nonce_buffer, seed);
         return *m_aes256_xof;
      }

      Botan::XOF& get_XOF(std::span<const uint8_t> seed, std::tuple<uint8_t, uint8_t> mpos) const override {
         m_aes256_xof->clear();
         const std::array<uint8_t, 12> iv{std::get<0>(mpos), std::get<1>(mpos), 0};
         m_aes256_xof->start(iv, seed);
         return *m_aes256_xof;
      }

   private:
      std::unique_ptr<HashFunction> m_sha512;
      std::unique_ptr<HashFunction> m_sha256;
      mutable std::unique_ptr<AES_256_CTR_XOF> m_aes256_xof;
};

}  // namespace Botan

#endif
