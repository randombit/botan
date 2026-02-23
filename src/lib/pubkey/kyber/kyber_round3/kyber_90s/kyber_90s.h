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
   protected:
      std::optional<std::array<uint8_t, 1>> seed_expansion_domain_separator(
         const KyberConstants& /*constants*/) const override {
         return {};
      }

      std::unique_ptr<HashFunction> create_G() const override { return HashFunction::create_or_throw("SHA-512"); }

      std::unique_ptr<HashFunction> create_H() const override { return HashFunction::create_or_throw("SHA-256"); }

      std::unique_ptr<HashFunction> create_J() const override {
         throw Invalid_State("Kyber-R3 in 90s mode does not support J()");
      }

      std::unique_ptr<HashFunction> create_KDF() const override { return HashFunction::create_or_throw("SHA-256"); }

      std::unique_ptr<Botan::XOF> create_PRF(std::span<const uint8_t> seed, const uint8_t nonce) const override {
         auto xof = std::make_unique<AES_256_CTR_XOF>();
         init_PRF(*xof, seed, nonce);
         return xof;
      }

      void init_PRF(Botan::XOF& xof, std::span<const uint8_t> seed, const uint8_t nonce) const override {
         xof.clear();
         dynamic_cast<AES_256_CTR_XOF&>(xof).start(std::array<uint8_t, 12>{nonce, 0}, seed);
      }

      std::unique_ptr<Botan::XOF> create_XOF(std::span<const uint8_t> seed,
                                             std::tuple<uint8_t, uint8_t> mpos) const override {
         auto xof = std::make_unique<AES_256_CTR_XOF>();
         init_XOF(*xof, seed, mpos);
         return xof;
      }

      void init_XOF(Botan::XOF& xof, std::span<const uint8_t> seed, std::tuple<uint8_t, uint8_t> mpos) const override {
         xof.clear();
         dynamic_cast<AES_256_CTR_XOF&>(xof).start(std::array<uint8_t, 12>{std::get<0>(mpos), std::get<1>(mpos), 0},
                                                   seed);
      }
};

}  // namespace Botan

#endif
