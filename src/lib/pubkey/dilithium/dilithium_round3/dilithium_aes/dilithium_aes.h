/*
* Symmetric primitives for dilithium AES
* (C) 2022 Jack Lloyd
* (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_AES_SYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_AES_SYM_PRIMITIVES_H_

#include <botan/internal/dilithium_round3_symmetric_primitives.h>

namespace Botan {

class Dilithium_AES_Symmetric_Primitives final : public Dilithium_Round3_Symmetric_Primitives {
   public:
      Dilithium_AES_Symmetric_Primitives(const DilithiumConstants& mode);
};

}  // namespace Botan

#endif
