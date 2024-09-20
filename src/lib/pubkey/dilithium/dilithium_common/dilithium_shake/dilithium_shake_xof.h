/*
* Asymmetric primitives for dilithium and ML-KEM using SHAKE as XOF
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_SHAKE_XOF_ADAPTER_H_
#define BOTAN_DILITHIUM_SHAKE_XOF_ADAPTER_H_

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/shake_xof.h>

namespace Botan {

class DilithiumShakeXOF final : public DilithiumXOF {
   public:
      Botan::XOF& XOF128(std::span<const uint8_t> seed, uint16_t nonce) const override {
         return XOF(m_xof_128, seed, nonce);
      }

      Botan::XOF& XOF256(std::span<const uint8_t> seed, uint16_t nonce) const override {
         return XOF(m_xof_256, seed, nonce);
      }

   private:
      static Botan::XOF& XOF(Botan::XOF& xof, std::span<const uint8_t> seed, uint16_t nonce) {
         xof.clear();
         xof.update(seed);
         xof.update(store_le(nonce));
         return xof;
      }

   private:
      mutable SHAKE_256_XOF m_xof_256;
      mutable SHAKE_128_XOF m_xof_128;
};

}  // namespace Botan

#endif
