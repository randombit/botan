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

#include <botan/internal/sp_types.h>
#include <optional>

namespace Botan {

class Sphincs_Address;
class Sphincs_Hash_Functions;
class Sphincs_Parameters;

/**
 * Implements a domain specific wrapper for the one-time signature scheme WOTS+
 * (Winternitz OTS). It is meant to be used inside SPHINCS+ and does not aim to
 * be applicable for other use cases. If this function is not used in a signing
 * operation (i.e. @p sign_leaf_idx is not set), @p wots_steps may be empty.
 */
BOTAN_TEST_API void wots_sign_and_pkgen(StrongSpan<WotsSignature> sig_out,
                                        StrongSpan<SphincsTreeNode> leaf_out,
                                        const SphincsSecretSeed& secret_seed,
                                        TreeNodeIndex leaf_idx,
                                        std::optional<TreeNodeIndex> sign_leaf_idx,
                                        const std::vector<WotsHashIndex>& wots_steps,
                                        Sphincs_Address& leaf_addr,
                                        Sphincs_Address& pk_addr,
                                        const Sphincs_Parameters& params,
                                        Sphincs_Hash_Functions& hashes);
/**
 * Reconstructs the WOTS public key from a given WOTS @p signature and
 * @p message. This is tailored for the use case in the SPHINCS+ implementation
 * and is not meant for general usability.
 */
BOTAN_TEST_API WotsPublicKey wots_public_key_from_signature(const SphincsTreeNode& hashed_message,
                                                            StrongSpan<const WotsSignature> signature,
                                                            Sphincs_Address& address,
                                                            const Sphincs_Parameters& params,
                                                            Sphincs_Hash_Functions& hashes);

/**
 * Given a @p msg construct the lengths (amount of hashes for signature) for each WOTS+ chain, including the checksum.
 */
BOTAN_TEST_API std::vector<WotsHashIndex> chain_lengths(const SphincsTreeNode& msg, const Sphincs_Parameters& params);

}  // namespace Botan

#endif
