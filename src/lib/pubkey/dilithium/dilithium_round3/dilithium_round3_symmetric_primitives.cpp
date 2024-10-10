/*
* Asymmetric primitives for Dilithium round 3
* (C) 2021-2024 Jack Lloyd
*     2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
*     2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
*     2024 Fabian Albert and René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dilithium_round3_symmetric_primitives.h>

#include <botan/rng.h>
#include <botan/internal/dilithium_algos.h>

namespace Botan {

secure_vector<uint8_t> Dilithium_Expanded_Keypair_Codec::encode_keypair(DilithiumInternalKeypair keypair) const {
   return Dilithium_Algos::encode_keypair(keypair).get();
}

DilithiumInternalKeypair Dilithium_Expanded_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key,
                                                                          DilithiumConstants mode) const {
   BOTAN_ARG_CHECK(mode.mode().is_available(), "Dilithium/ML-DSA mode is not available in this build");
   BOTAN_ARG_CHECK(private_key.size() == mode.private_key_bytes(),
                   "dilithium private key does not have the correct byte count");
   return Dilithium_Algos::decode_keypair(StrongSpan<const DilithiumSerializedPrivateKey>(private_key),
                                          std::move(mode));
}

}  // namespace Botan
