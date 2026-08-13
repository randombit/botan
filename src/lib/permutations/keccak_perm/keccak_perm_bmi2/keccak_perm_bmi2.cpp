/*
* Keccak-FIPS
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/keccak_perm_round.h>

namespace Botan {

void BOTAN_FN_ISA_BMI2 Keccak_Permutation::permute_bmi2() {
   uint64_t T[25];

   for(size_t i = 0; i != 24; i += 2) {
      Keccak_Permutation_round(T, state().data(), KECCAK_RC[i + 0]);
      Keccak_Permutation_round(state().data(), T, KECCAK_RC[i + 1]);
   }
}

}  // namespace Botan
