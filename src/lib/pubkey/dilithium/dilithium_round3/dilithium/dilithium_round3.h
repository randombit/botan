/*
* Asymmetric primitives for Dilithium round 3
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_round3_symmetric_primitives.h>

#include <botan/internal/dilithium_shake_xof.h>

namespace Botan {

class Dilithium_Symmetric_Primitives final : public Dilithium_Round3_Symmetric_Primitives {
   public:
      Dilithium_Symmetric_Primitives(const DilithiumConstants& mode) :
            Dilithium_Round3_Symmetric_Primitives(mode, std::make_unique<DilithiumShakeXOF>()) {}
};

}  // namespace Botan

#endif
