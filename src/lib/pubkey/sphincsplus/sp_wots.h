/*
 * WOTS+ - Winternitz One Time Signature+
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_WOTS_H_
#define BOTAN_SP_WOTS_H_

#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/sp_parameters.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_types.h>
#include <botan/concepts.h>

#include <cstdint>
#include <memory>

namespace Botan {

class HashFunction;
class Sphincs_Address;
class Sphincs_Hash_Functions;

/**
 * Implements a domain specific wrapper for the one-time signature scheme
 * WOTS+ (Winternitz OTS). It is meant to be used inside SPHINCS+
 * and does not aim to be applicable for other use cases.
 */
BOTAN_TEST_API std::pair<WotsPublicKey, WotsSignature> wots_sign(const SphincsHashedMessage& hashed_message,
                                                                 const SphincsSecretSeed& secret_seed,
                                                                 const SphincsPublicSeed& public_seed,
                                                                 const Sphincs_Address& address,
                                                                 const Sphincs_Parameters& params,
                                                                 Sphincs_Hash_Functions& hash);

//TODO: Do we need this interface?
BOTAN_TEST_API WotsPublicKey wots_calc_public_key(const SphincsSecretSeed& secret_seed,
                                                                 const SphincsPublicSeed& public_seed,
                                                                 const Sphincs_Address& address,
                                                                 const Sphincs_Parameters& params,
                                                                 Sphincs_Hash_Functions& hash);

/**
 * Reconstructs the WOTS public key from a given WOTS @p signature and
 * @p message. This is tailored for the use case in the SPHINCS+ implementation
 * and is not meant for general usability.
 */
BOTAN_TEST_API WotsPublicKey wots_public_key_from_signature(const SphincsHashedMessage& hashed_message,
                                                            const WotsSignature& signature,
                                                            const SphincsPublicSeed& public_seed,
                                                            Sphincs_Address& address,
                                                            const Sphincs_Parameters& params,
                                                            Sphincs_Hash_Functions& hashes);

//BOTAN_TEST_API ForsIndices fors_message_to_indices(std::span<const uint8_t> message, const Sphincs_Parameters& params);

}

#endif
