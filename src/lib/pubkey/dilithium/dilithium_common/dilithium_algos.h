/*
 * Crystals Dilithium Internal Algorithms
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_DILITHIUM_ALGOS_H_
#define BOTAN_DILITHIUM_ALGOS_H_

#include <botan/internal/dilithium_types.h>

// ML-DSA does encode the private key only by its random seeds.
#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   #define BOTAN_NEEDS_DILITHIUM_PRIVATE_KEY_ENCODING 1
#endif

namespace Botan::Dilithium_Algos {

DilithiumInternalKeypair expand_keypair(DilithiumSeedRandomness xi, DilithiumConstants mode);

DilithiumPolyMatNTT expand_A(StrongSpan<const DilithiumSeedRho> rho, const DilithiumConstants& mode);

std::pair<DilithiumPolyVec, DilithiumPolyVec> expand_s(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                                                       const DilithiumConstants& mode);

DilithiumPolyVec expand_mask(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                             uint16_t nonce,
                             const DilithiumConstants& mode);

DilithiumSerializedCommitment encode_commitment(const DilithiumPolyVec& w1, const DilithiumConstants& mode);

DilithiumPoly sample_in_ball(StrongSpan<const DilithiumCommitmentHash> seed, const DilithiumConstants& mode);

std::optional<std::tuple<DilithiumCommitmentHash, DilithiumPolyVec, DilithiumPolyVec>> decode_signature(
   StrongSpan<const DilithiumSerializedSignature> sig, const DilithiumConstants& mode);

DilithiumSerializedSignature encode_signature(StrongSpan<const DilithiumCommitmentHash> c,
                                              const DilithiumPolyVec& response,
                                              const DilithiumPolyVec& hint,
                                              const DilithiumConstants& mode);

DilithiumSerializedPublicKey encode_public_key(StrongSpan<const DilithiumSeedRho> rho,
                                               const DilithiumPolyVec& t1,
                                               const DilithiumConstants& mode);

std::pair<DilithiumSeedRho, DilithiumPolyVec> decode_public_key(StrongSpan<const DilithiumSerializedPublicKey> pk,
                                                                const DilithiumConstants& mode);

#if BOTAN_NEEDS_DILITHIUM_PRIVATE_KEY_ENCODING

DilithiumSerializedPrivateKey encode_keypair(const DilithiumInternalKeypair& keypair);

DilithiumInternalKeypair decode_keypair(StrongSpan<const DilithiumSerializedPrivateKey> sk, DilithiumConstants mode);

#endif

std::pair<DilithiumPolyVec, DilithiumPolyVec> power2round(const DilithiumPolyVec& vec);

std::pair<DilithiumPolyVec, DilithiumPolyVec> decompose(const DilithiumPolyVec& vec, const DilithiumConstants& mode);

DilithiumPolyVec make_hint(const DilithiumPolyVec& z, const DilithiumPolyVec& r, const DilithiumConstants& mode);

void use_hint(DilithiumPolyVec& vec, const DilithiumPolyVec& hints, const DilithiumConstants& mode);

bool infinity_norm_within_bound(const DilithiumPolyVec& vec, size_t bound);

}  // namespace Botan::Dilithium_Algos

#endif
