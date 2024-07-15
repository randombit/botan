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
#include <botan/internal/shake_xof.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class Dilithium_Common_Symmetric_Primitives : public Dilithium_Symmetric_Primitives {
   public:
      Dilithium_Common_Symmetric_Primitives(size_t collision_strength_in_bytes) :
            Dilithium_Symmetric_Primitives(collision_strength_in_bytes) {}

      Botan::XOF& XOF(XofType type, std::span<const uint8_t> seed, uint16_t nonce) const override {
         auto& xof = [&]() -> Botan::XOF& {
            switch(type) {
               case XofType::k128:
                  return m_xof_128;
               case XofType::k256:
                  return m_xof_256;
            }

            BOTAN_ASSERT_UNREACHABLE();
         }();

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
