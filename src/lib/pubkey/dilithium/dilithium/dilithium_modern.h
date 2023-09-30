/*
* Asymmetric primitives for dilithium
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_COMMON_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_COMMON_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/shake.h>
#include <botan/internal/shake_xof.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class Dilithium_Common_Symmetric_Primitives : public Dilithium_Symmetric_Primitives {
   public:
      std::unique_ptr<Botan::XOF> XOF(XofType type, std::span<const uint8_t> seed, uint16_t nonce) const override {
         const auto xof_type = [&] {
            switch(type) {
               case XofType::k128:
                  return "SHAKE-128";
               case XofType::k256:
                  return "SHAKE-256";
            }

            BOTAN_ASSERT_UNREACHABLE();
         }();

         std::array<uint8_t, sizeof(nonce)> nonce_buffer;
         store_le(nonce, nonce_buffer.data());

         auto xof = Botan::XOF::create_or_throw(xof_type);
         xof->update(seed);
         xof->update(nonce_buffer);
         return xof;
      }
};

}  // namespace Botan

#endif
