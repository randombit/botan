/*
* Symmetric primitives for dilithium
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_ML_DSA_IPD_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_ML_DSA_IPD_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/rng.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/shake.h>
#include <botan/internal/shake_xof.h>
#include <botan/internal/stl_util.h>

#include <array>
#include <memory>
#include <vector>

namespace Botan {

class ML_DSA_IPD_Common_Symmetric_Primitives : public Dilithium_Symmetric_Primitives {
   public:
      //TODO: Restructure s.t. DIlithium w/o AES and ML-DSA-IPD share this code, right now it is just copied from there
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

      secure_vector<uint8_t> calc_rhoprime(RandomNumberGenerator& rng,
                                           const secure_vector<uint8_t>& key,
                                           const std::vector<uint8_t>& mu,
                                           bool randomized) const override {
         const auto& rnd = (randomized) ? rng.random_vec(DilithiumModeConstants::RNDBYTES)
                                        : secure_vector<uint8_t>(DilithiumModeConstants::RNDBYTES, 0);
         return CRH(concat(key, rnd, mu), DilithiumModeConstants::CRHBYTES);
      }
};

}  // namespace Botan

#endif
