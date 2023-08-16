/*
* Asymmetric primitives for dilithium AES
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_AES_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_AES_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/internal/aes_crystals_xof.h>
#include <botan/internal/loadstor.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class Dilithium_AES_Symmetric_Primitives : public Dilithium_Symmetric_Primitives {
   public:
      // AES mode always uses AES-256, regardless of the XofType
      std::unique_ptr<Botan::XOF> XOF(XofType /* type */, std::span<const uint8_t> seed, uint16_t nonce) const final {
         // Algorithm Spec V. 3.1 Section 5.3
         //    In the AES variant, the first 32 bytes of rhoprime are used as
         //    the key and i is extended to a 12 byte nonce for AES-256 in
         //    counter mode.
         //
         // I.e. when the XOF is used in "ExpandS" `seed` (aka rhoprime) will be
         // 64 bytes long and must be truncated to the 32 most significant bytes.
         BOTAN_ASSERT_NOMSG(seed.size() >= 32);

         const std::array<uint8_t, 12> iv{get_byte<1>(nonce), get_byte<0>(nonce), 0};
         const auto key = seed.first(32);

         auto xof = std::make_unique<AES_256_CTR_XOF>();
         xof->start(iv, key);
         return xof;
      }
};

}  // namespace Botan

#endif
