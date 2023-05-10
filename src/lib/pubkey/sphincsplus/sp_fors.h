/*
 * FORS - Forest of Random Subsets
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SPHINCS_PLUS_FORS_H_
#define BOTAN_SPHINCS_PLUS_FORS_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/sp_address.h>
#include <botan/sp_parameters.h>
#include <botan/internal/sp_types.h>
#include <botan/internal/sp_hash.h>

#include <memory>

namespace Botan {

class HashFunction;
class Sphincs_Address;
class Sphincs_Hash_Functions;

/**
 * Implements a domain specific wrapper for the few-times signature scheme
 * FORS (Forest of Random Subsets). It is meant to be used inside SPHINCS+
 * and does not aim to be applicable for other use cases.
 */
BOTAN_TEST_API std::pair<ForsPublicKey, ForsSignature> fors_sign(const SphincsHashedMessage& hashed_message,
                                                                 const SphincsSecretSeed& secret_seed,
                                                                 const SphincsPublicSeed& public_seed,
                                                                 const Sphincs_Address& address,
                                                                 const Sphincs_Parameters& params,
                                                                 Sphincs_Hash_Functions& hash);

/**
 * Reconstructs the FORS public key from a given FORS @p signature and
 * @p message. This is tailored for the use case in the SPHINCS+ implementation
 * and is not meant for general usability.
 */
BOTAN_TEST_API ForsPublicKey fors_public_key_from_signature(const SphincsHashedMessage& hashed_message,
                                                            const ForsSignature& signature,
                                                            const SphincsPublicSeed& public_seed,
                                                            const Sphincs_Address& address,
                                                            const Sphincs_Parameters& params,
                                                            Sphincs_Hash_Functions& hash);

BOTAN_TEST_API ForsIndices fors_message_to_indices(std::span<const uint8_t> message, const Sphincs_Parameters& params);

}

#endif
