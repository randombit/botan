/*
 * Strong Type definitions used throughout the Dilithium implementation
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_DILITHIUM_TYPES_H_
#define BOTAN_DILITHIUM_TYPES_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/dilithium_polynomial.h>

namespace Botan {

class Dilithium_PublicKeyInternal;
class Dilithium_PrivateKeyInternal;

using DilithiumPolyNTT = Botan::CRYSTALS::Polynomial<DilithiumPolyTraits, Botan::CRYSTALS::Domain::NTT>;
using DilithiumPolyVecNTT = Botan::CRYSTALS::PolynomialVector<DilithiumPolyTraits, Botan::CRYSTALS::Domain::NTT>;
using DilithiumPolyMatNTT = Botan::CRYSTALS::PolynomialMatrix<DilithiumPolyTraits>;

using DilithiumPoly = Botan::CRYSTALS::Polynomial<DilithiumPolyTraits, Botan::CRYSTALS::Domain::Normal>;
using DilithiumPolyVec = Botan::CRYSTALS::PolynomialVector<DilithiumPolyTraits, Botan::CRYSTALS::Domain::Normal>;

/// Principal seed used to generate Dilithium key pairs
using DilithiumSeedRandomness = Strong<secure_vector<uint8_t>, struct DilithiumSeedRandomness_>;

/// Public seed to sample the polynomial matrix A from
using DilithiumSeedRho = Strong<std::vector<uint8_t>, struct DilithiumPublicSeed_>;

/// Private seed to sample the polynomial vectors s1 and s2 from
using DilithiumSeedRhoPrime = Strong<secure_vector<uint8_t>, struct DilithiumSeedRhoPrime_>;

/// Optional randomness 'rnd' used for rho prime computation in ML-DSA
using DilithiumOptionalRandomness = Strong<secure_vector<uint8_t>, struct DilithiumOptionalRandomness_>;

/// Private seed K used during signing
using DilithiumSigningSeedK = Strong<secure_vector<uint8_t>, struct DilithiumSeedK_>;

/// Serialized private key data
using DilithiumSerializedPrivateKey = Strong<secure_vector<uint8_t>, struct DilithiumSerializedPrivateKey_>;

/// Serialized public key data (result of pkEncode(pk))
using DilithiumSerializedPublicKey = Strong<std::vector<uint8_t>, struct DilithiumSerializedPublicKey_>;

/// Hash value of the serialized public key data
/// (result of H(BytesToBits(pkEncode(pk)), also referred to as 'tr')
using DilithiumHashedPublicKey = Strong<std::vector<uint8_t>, struct DilithiumHashedPublicKey_>;

/// Representation of the message to be signed
using DilithiumMessageRepresentative = Strong<std::vector<uint8_t>, struct DilithiumMessageRepresentative_>;

/// Serialized signature data
using DilithiumSerializedSignature = Strong<std::vector<uint8_t>, struct DilithiumSerializedSignature_>;

/// Serialized representation of a commitment w1
using DilithiumSerializedCommitment = Strong<std::vector<uint8_t>, struct DilithiumSerializedCommitment_>;

/// Hash of the message representative and the signer's commitment
using DilithiumCommitmentHash = Strong<std::vector<uint8_t>, struct DilithiumCommitmentHash_>;

/// Internal representation of a Dilithium key pair
using DilithiumInternalKeypair =
   std::pair<std::shared_ptr<Dilithium_PublicKeyInternal>, std::shared_ptr<Dilithium_PrivateKeyInternal>>;

}  // namespace Botan

#endif
