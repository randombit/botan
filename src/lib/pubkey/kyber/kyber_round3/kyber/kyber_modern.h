/*
 * Symmetric primitives for Kyber (modern (non-90s) mode)
 * (C) 2022-2024 Jack Lloyd
 * (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_MODERN_H_
#define BOTAN_KYBER_MODERN_H_

#include <botan/internal/kyber_symmetric_primitives.h>

#include <botan/hash.h>
#include <botan/xof.h>
#include <array>
#include <memory>

namespace Botan {

class Kyber_Modern_Symmetric_Primitives final : public Kyber_Symmetric_Primitives {
   protected:
      std::optional<std::array<uint8_t, 1>> seed_expansion_domain_separator(
         const KyberConstants& /*constants*/) const override {
         return {};
      }

      std::unique_ptr<HashFunction> create_G() const override { return HashFunction::create_or_throw("SHA-3(512)"); }

      std::unique_ptr<HashFunction> create_H() const override { return HashFunction::create_or_throw("SHA-3(256)"); }

      std::unique_ptr<HashFunction> create_J() const override { throw Invalid_State("Kyber-R3 does not support J()"); }

      std::unique_ptr<HashFunction> create_KDF() const override {
         return HashFunction::create_or_throw("SHAKE-256(256)");
      }

      std::unique_ptr<Botan::XOF> create_PRF(std::span<const uint8_t> seed, const uint8_t nonce) const override {
         auto xof = Botan::XOF::create_or_throw("SHAKE-256");
         init_PRF(*xof, seed, nonce);
         return xof;
      }

      void init_PRF(Botan::XOF& xof, std::span<const uint8_t> seed, const uint8_t nonce) const override {
         xof.clear();
         xof.update(seed);
         xof.update({&nonce, 1});
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

         const std::array<uint8_t, 2> pos = {std::get<0>(matrix_position), std::get<1>(matrix_position)};
         xof.update(pos);
      }
};

}  // namespace Botan

#endif
