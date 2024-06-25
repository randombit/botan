/**
 * Symmetric primitives for dilithium
 *
 * (C) 2022-2023 Jack Lloyd
 * (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_symmetric_primitives.h>

#if defined(BOTAN_HAS_DILITHIUM)
   #include <botan/internal/dilithium_modern.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/internal/dilithium_aes.h>
#endif

namespace Botan {

std::unique_ptr<Dilithium_Symmetric_Primitives> Dilithium_Symmetric_Primitives::create(const DilithiumConstants& mode) {
#if BOTAN_HAS_DILITHIUM
   if(mode.is_modern()) {
      return std::make_unique<Dilithium_Common_Symmetric_Primitives>(mode.commitment_hash_full_bytes());
   }
#endif

#if BOTAN_HAS_DILITHIUM_AES
   if(mode.is_aes()) {
      return std::make_unique<Dilithium_AES_Symmetric_Primitives>(mode.commitment_hash_full_bytes());
   }
#endif

   throw Not_Implemented("requested Dilithium mode is not enabled in this build");
}

}  // namespace Botan
