/*
 * Symmetric primitives for Kyber (modern (non-90s) mode)
 * (C) 2022 Jack Lloyd
 * (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_MODERN_H_
#define BOTAN_KYBER_MODERN_H_

#include <botan/hash.h>
#include <botan/xof.h>

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/loadstor.h>

#include <memory>

namespace Botan {

class Kyber_Modern_Symmetric_Primitives : public Kyber_Symmetric_Primitives {
   public:
      Kyber_Modern_Symmetric_Primitives() :
            m_sha3_512(HashFunction::create_or_throw("SHA-3(512)")),
            m_sha3_256(HashFunction::create_or_throw("SHA-3(256)")),
            m_shake256_256(HashFunction::create_or_throw("SHAKE-256(256)")),
            m_shake128(Botan::XOF::create_or_throw("SHAKE-128")),
            m_shake256(Botan::XOF::create_or_throw("SHAKE-256")) {}

   protected:
      HashFunction& get_G() const override { return *m_sha3_512; }

      HashFunction& get_H() const override { return *m_sha3_256; }

      HashFunction& get_KDF() const override { return *m_shake256_256; }

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
