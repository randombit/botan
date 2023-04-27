/*
 * FORS - Forest of Random Subsets
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SPHINCS_PLUS_FORS_H_
#define BOTAN_SPHINCS_PLUS_FORS_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/sp_address.h>

#include <memory>

namespace Botan {

class HashFunction;
class Sphincs_Address;

using SphincsPublicSeed = Strong<std::vector<uint8_t>, struct SphincsPublicSeed_>;
using SphincsSecretSeed = Strong<secure_vector<uint8_t>, struct SphincsSecretSeed_>;
using ForsPublicKey = Strong<std::vector<uint8_t>, struct ForsPublicKey_>;
using ForsSignature = Strong<std::vector<uint8_t>, struct ForsSignature_>;
using ForsIndices = Strong<std::vector<uint32_t>, struct ForsIndices_>;
// using SphincsAddress = Strong<std::array<uint32_t, 8>, struct SphincsAddress_>;

struct FORS_Parameters
   {
   /// Security parameter in bytes
   size_t n;

   /// Number of trees
   size_t k;

   /// Height of the trees or `log(t)` with t being the number of leaves
   size_t a;
   };

/**
 * Implements a domain specific wrapper for the few-times signature scheme
 * FORS (Forest of Random Subsets). It is meant to be used inside SPHINCS+
 * and does not aim to be applicable for other use cases.
 */
BOTAN_TEST_API std::pair<ForsPublicKey, ForsSignature> fors_sign(std::span<const uint8_t> message, // TODO: replace by a strong type once we know what exactly will be signed
                                                                 const SphincsSecretSeed& secret_seed,
                                                                 const SphincsPublicSeed& public_seed,
                                                                 const Sphincs_Address& address,
                                                                 const FORS_Parameters& params,
                                                                 HashFunction& hash);

/**
 * Reconstructs the FORS public key from a given FORS @p signature and
 * @p message. This is tailored for the use case in the SPHINCS+ implementation
 * and is not meant for general usability.
 */
BOTAN_TEST_API ForsPublicKey fors_public_key_from_signature(std::span<const uint8_t> message,  // TODO: replace by a strong type once we know what exactly will be signed
                                                            const ForsSignature& signature,
                                                            const SphincsPublicSeed& public_seed,
                                                            const Sphincs_Address& address,
                                                            const FORS_Parameters& params,
                                                            HashFunction& hash);

BOTAN_TEST_API ForsIndices fors_message_to_indices(std::span<const uint8_t> message, const FORS_Parameters& params);

}

#endif
