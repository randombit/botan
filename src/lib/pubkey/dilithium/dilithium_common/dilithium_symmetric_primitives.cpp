/**
 * Symmetric primitives for dilithium
 *
 * (C) 2022-2023 Jack Lloyd
 * (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
 * (C) 2024      Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_symmetric_primitives.h>

#if defined(BOTAN_HAS_DILITHIUM)
   #include <botan/internal/dilithium_round3.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/internal/dilithium_aes.h>
#endif

#if defined(BOTAN_HAS_ML_DSA)
   #include <botan/internal/ml_dsa_impl.h>
#endif

namespace Botan {

std::unique_ptr<Dilithium_Symmetric_Primitives_Base> Dilithium_Symmetric_Primitives_Base::create(
   const DilithiumConstants& mode) {
#if defined(BOTAN_HAS_DILITHIUM)
   if(mode.is_modern() && !mode.is_ml_dsa()) {
      return std::make_unique<Dilithium_Symmetric_Primitives>(mode);
   }
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   if(mode.is_aes()) {
      return std::make_unique<Dilithium_AES_Symmetric_Primitives>(mode);
   }
#endif

#if defined(BOTAN_HAS_ML_DSA)
   if(mode.is_ml_dsa()) {
      return std::make_unique<ML_DSA_Symmetric_Primitives>(mode);
   }
#endif

   throw Not_Implemented("requested ML-DSA/Dilithium mode is not implemented in this build");
}

}  // namespace Botan
