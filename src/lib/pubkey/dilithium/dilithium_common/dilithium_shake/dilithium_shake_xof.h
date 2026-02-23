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

namespace Botan {

class DilithiumShakeXOF final : public DilithiumXOF {
   public:
      DilithiumShakeXOF() = default;

      ~DilithiumShakeXOF() override;

      DilithiumShakeXOF(const DilithiumShakeXOF& other) = delete;
      DilithiumShakeXOF(DilithiumShakeXOF&& other) = delete;
      DilithiumShakeXOF& operator=(const DilithiumShakeXOF& other) = delete;
      DilithiumShakeXOF& operator=(DilithiumShakeXOF&& other) = delete;

      std::unique_ptr<XOF> XOF128(std::span<const uint8_t> seed, uint16_t nonce) const override {
         return createXOF("SHAKE-128", seed, nonce);
      }

      std::unique_ptr<XOF> XOF256(std::span<const uint8_t> seed, uint16_t nonce) const override {
         return createXOF("SHAKE-256", seed, nonce);
      }

   private:
      static std::unique_ptr<Botan::XOF> createXOF(std::string_view name,
                                                   std::span<const uint8_t> seed,
                                                   uint16_t nonce);
};

}  // namespace Botan

#endif
