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

namespace Botan {

DilithiumPolyMatNTT dilithium_expand_A(StrongSpan<const DilithiumSeedRho> rho, const DilithiumConstants& mode);
std::pair<DilithiumPolyVec, DilithiumPolyVec> dilithium_expand_s(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                                                                 const DilithiumConstants& mode);
DilithiumPolyVec dilithium_expand_mask(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                                       uint16_t nonce,
                                       const DilithiumConstants& mode);

DilithiumSerializedCommitment dilithium_encode_commitment(const DilithiumPolyVec& w1, const DilithiumConstants& mode);

DilithiumPoly dilithium_sample_in_ball(StrongSpan<const DilithiumCommitmentHash> seed, const DilithiumConstants& mode);

std::optional<std::tuple<DilithiumCommitmentHash, DilithiumPolyVec, DilithiumPolyVec>> dilithium_decode_signature(
   StrongSpan<const DilithiumSerializedSignature> sig, const DilithiumConstants& mode);

DilithiumSerializedSignature dilithium_encode_signature(StrongSpan<const DilithiumCommitmentHash> c,
                                                        const DilithiumPolyVec& response,
                                                        const DilithiumPolyVec& hint,
                                                        const DilithiumConstants& mode);

DilithiumSerializedPublicKey dilithium_encode_public_key(StrongSpan<const DilithiumSeedRho> rho,
                                                         const DilithiumPolyVec& t1,
                                                         const DilithiumConstants& mode);

std::pair<DilithiumSeedRho, DilithiumPolyVec> dilithium_decode_public_key(
   StrongSpan<const DilithiumSerializedPublicKey> pk, const DilithiumConstants& mode);

DilithiumSerializedPrivateKey dilithium_encode_private_key(StrongSpan<const DilithiumSeedRho> rho,
                                                           StrongSpan<const DilithiumHashedPublicKey> tr,
                                                           StrongSpan<const DilithiumSigningSeedK> key,
                                                           const DilithiumPolyVec& s1,
                                                           const DilithiumPolyVec& s2,
                                                           const DilithiumPolyVec& t0,
                                                           const DilithiumConstants& mode);

std::tuple<DilithiumSeedRho,
           DilithiumSigningSeedK,
           DilithiumHashedPublicKey,
           DilithiumPolyVec,
           DilithiumPolyVec,
           DilithiumPolyVec>
dilithium_decode_private_key(StrongSpan<const DilithiumSerializedPrivateKey> sk, const DilithiumConstants& mode);

std::pair<DilithiumPolyVec, DilithiumPolyVec> dilithium_power2round(const DilithiumPolyVec& vec);

std::pair<DilithiumPolyVec, DilithiumPolyVec> dilithium_decompose(const DilithiumPolyVec& vec,
                                                                  const DilithiumConstants& mode);

DilithiumPolyVec dilithium_make_hint(const DilithiumPolyVec& z,
                                     const DilithiumPolyVec& r,
                                     const DilithiumConstants& mode);

void dilithium_use_hint(DilithiumPolyVec& vec, const DilithiumPolyVec& hints, const DilithiumConstants& mode);

bool dilithium_infinity_norm_within_bound(const DilithiumPolyVec& vec, size_t bound);

}  // namespace Botan

#endif
