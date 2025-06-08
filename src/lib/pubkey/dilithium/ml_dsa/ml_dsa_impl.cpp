/*
* Asymmetric primitives for ML-DSA
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ml_dsa_impl.h>

#include <botan/internal/dilithium_algos.h>

namespace Botan {

secure_vector<uint8_t> ML_DSA_Expanding_Keypair_Codec::encode_keypair(DilithiumInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& seed = keypair.second->seed();
   BOTAN_ARG_CHECK(seed.has_value(), "Cannot encode keypair without the private seed");
   return seed.value().get();
}

DilithiumInternalKeypair ML_DSA_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key_seed,
                                                                        DilithiumConstants mode) const {
   return Dilithium_Algos::expand_keypair(DilithiumSeedRandomness(private_key_seed), std::move(mode));
}

}  // namespace Botan
