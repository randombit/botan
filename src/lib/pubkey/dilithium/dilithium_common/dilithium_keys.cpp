/*
 * Crystals Dilithium Internal Key Types
 *
 * (C) 2024 Jack Lloyd
 *     2024 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_keys.h>

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/internal/dilithium_round3_symmetric_primitives.h>
#endif

#if defined(BOTAN_HAS_ML_DSA)
   #include <botan/internal/ml_dsa_impl.h>
#endif

namespace Botan {

std::unique_ptr<Dilithium_Keypair_Codec> Dilithium_Keypair_Codec::create(DilithiumMode mode) {
#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   if(mode.is_dilithium_round3()) {
      return std::make_unique<Dilithium_Expanded_Keypair_Codec>();
   }
#endif

#if defined(BOTAN_HAS_ML_DSA)
   if(mode.is_ml_dsa()) {
      return std::make_unique<ML_DSA_Expanding_Keypair_Codec>();
   }
#endif

   throw Not_Implemented("requested ML-DSA/Dilithium mode is not implemented in this build");
}

}  // namespace Botan
