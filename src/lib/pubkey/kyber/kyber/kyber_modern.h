/*
 * Symmetric primitives for Kyber (modern (non-90s) mode)
 * (C) 2022 Jack Lloyd
 * (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_MODERN_H_
#define BOTAN_KYBER_MODERN_H_

#include <botan/hash.h>
#include <botan/xof.h>

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/shake.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class Kyber_Modern_Symmetric_Primitives : public Kyber_Symmetric_Primitives {
   public:
      Kyber_Modern_Symmetric_Primitives() :
            m_sha3_512(HashFunction::create_or_throw("SHA-3(512)")),
            m_sha3_256(HashFunction::create_or_throw("SHA-3(256)")),
            m_shake256_256(HashFunction::create_or_throw("SHAKE-256(256)")),
            m_shake128(Botan::XOF::create_or_throw("SHAKE-128")) {}

      std::unique_ptr<HashFunction> G() const override { return m_sha3_512->new_object(); }

      std::unique_ptr<HashFunction> H() const override { return m_sha3_256->new_object(); }

      std::unique_ptr<HashFunction> KDF() const override { return m_shake256_256->new_object(); }

      Botan::XOF& XOF(std::span<const uint8_t> seed, std::tuple<uint8_t, uint8_t> matrix_position) const override {
         m_shake128->clear();
         m_shake128->update(seed);

         const std::array<uint8_t, 2> matrix_position_buffer{std::get<0>(matrix_position),
                                                             std::get<1>(matrix_position)};
         m_shake128->update(matrix_position_buffer);
         return *m_shake128;
      }

      secure_vector<uint8_t> PRF(std::span<const uint8_t> seed,
                                 const uint8_t nonce,
                                 const size_t outlen) const override {
         SHAKE_256 kdf(outlen * 8);
         kdf.update(seed.data(), seed.size());
         kdf.update(nonce);
         return kdf.final();
      }

   private:
      std::unique_ptr<HashFunction> m_sha3_512;
      std::unique_ptr<HashFunction> m_sha3_256;
      std::unique_ptr<HashFunction> m_shake256_256;
      std::unique_ptr<Botan::XOF> m_shake128;
};

}  // namespace Botan

#endif
