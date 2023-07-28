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

#include <botan/internal/shake.h>
#include <botan/internal/shake_cipher.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class Dilithium_Common_Symmetric_Primitives : public Dilithium_Symmetric_Primitives {
   public:
      std::unique_ptr<StreamCipher> XOF(XofType type, std::span<const uint8_t> seed, uint16_t nonce) const override {
         // Input is a concatination of seed | nonce used as input for shake128
         std::vector<uint8_t> input;
         input.reserve(seed.size() + 2);
         input.insert(input.end(), seed.begin(), seed.end());
         input.push_back(static_cast<uint8_t>(nonce));
         input.push_back(static_cast<uint8_t>(nonce >> 8));

         std::unique_ptr<StreamCipher> cipher;
         switch(type) {
            case XofType::k128:
               cipher = std::make_unique<SHAKE_128_Cipher>();
               break;
            case XofType::k256:
               cipher = std::make_unique<SHAKE_256_Cipher>();
               break;
         }

         cipher->set_key(input);

         return cipher;
      }
};

}  // namespace Botan

#endif
