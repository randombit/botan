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

#if defined(BOTAN_HAS_DILITHIUM_MODERN)
   #include <botan/internal/dilithium_modern.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/internal/dilithium_aes.h>
#endif

namespace Botan {

std::unique_ptr<Dilithium_Symmetric_Primitives> Dilithium_Symmetric_Primitives::create(const DilithiumConstants& mode) {
   if(!mode.mode().is_available()) {
      throw Not_Implemented("requested Dilithium mode is not enabled in this build");
   }

   if(mode.is_modern()) {
      return std::make_unique<Dilithium_Common_Symmetric_Primitives>(mode);
   } else /* AES mode */ {
      return std::make_unique<Dilithium_AES_Symmetric_Primitives>(mode);
   }
}

DilithiumSeedRhoPrime Dilithium_Symmetric_Primitives::calc_rhoprime(RandomNumberGenerator& rng,
                                                                    StrongSpan<const DilithiumSigningSeedK> k,
                                                                    StrongSpan<const DilithiumMessageRepresentative> mu,
                                                                    bool randomized) const {
   if(m_mode.is_ml_dsa_ipd()) {
      // ML-KEM IPD, Algor. 2, l. 7,8:
      //   rnd <- {0, 1}^256 (For the optional deterministic variant, substitute rnd <- {0}^256)
      //   p' <- H(K || rnd || mu, 512)
      const auto rnd = [&] {
         DilithiumOptionalRandomness optional_randomness(DilithiumConstants::OPTIONAL_RANDOMNESS_BYTES);
         if(randomized) {
            rng.randomize(optional_randomness);
         }
         return optional_randomness;
      }();
      return H(k, rnd, mu);

   } else /* is Dilithium R3 */ {
      // Dilitihium R3, Figure 4, l. 12:
      //   p' in {0, 1}^512 := H(K || mu) (or p' <- {0, 1}^512 for randomized signing)
      return (randomized) ? rng.random_vec<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES) : H(k, mu);
   }
}

}  // namespace Botan
