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

#include <botan/xof.h>

namespace Botan {

class DilithiumShakeXOF final : public DilithiumXOF {
   public:
      DilithiumShakeXOF();

      ~DilithiumShakeXOF() override;

      DilithiumShakeXOF(const DilithiumShakeXOF& other) = delete;
      DilithiumShakeXOF(DilithiumShakeXOF&& other) = delete;
      DilithiumShakeXOF& operator=(const DilithiumShakeXOF& other) = delete;
      DilithiumShakeXOF& operator=(DilithiumShakeXOF&& other) = delete;

      Botan::XOF& XOF128(std::span<const uint8_t> seed, uint16_t nonce) const override {
         setupXOF(*m_xof_128, seed, nonce);
         return (*m_xof_128);
      }

      Botan::XOF& XOF256(std::span<const uint8_t> seed, uint16_t nonce) const override {
         setupXOF(*m_xof_256, seed, nonce);
         return (*m_xof_256);
      }

   private:
      static void setupXOF(Botan::XOF& xof, std::span<const uint8_t> seed, uint16_t nonce) {
         const uint8_t nonce8[2] = {static_cast<uint8_t>(nonce), static_cast<uint8_t>(nonce >> 8)};

         xof.clear();
         xof.update(seed);
         xof.update(nonce8);
      }

   private:
      std::unique_ptr<XOF> m_xof_256;
      std::unique_ptr<XOF> m_xof_128;
};

}  // namespace Botan

#endif
