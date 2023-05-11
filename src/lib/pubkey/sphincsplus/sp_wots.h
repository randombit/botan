/*
 * WOTS+ - Winternitz One Time Signature+
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
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
BOTAN_TEST_API void wots_gen_leaf_spec( std::span<uint8_t> sig_out,
                               std::span<uint8_t> pk_out,
                               const SphincsSecretSeed& secret_seed,
                               const SphincsPublicSeed& public_seed,
                               uint32_t leaf_idx,
                               uint32_t sign_leaf_idx,
                               WotsBaseWChunks& wots_steps,
                               Sphincs_Address& leaf_addr,
                               Sphincs_Address& pk_addr,
                               const Sphincs_Parameters& params,
                               Sphincs_Hash_Functions& hashes);

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

/**
 * Given a @p msg construct the lengths (amount of hashes for signature) for each WOTS+ chain, including the checksum.
 */
BOTAN_TEST_API WotsBaseWChunks chain_lengths(const SphincsHashedMessage& msg, const Sphincs_Parameters& params);

}

#endif
