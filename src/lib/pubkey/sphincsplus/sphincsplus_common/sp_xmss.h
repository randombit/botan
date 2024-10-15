/*
 * SLH-DSA's XMSS - eXtended Merkle Signature Scheme (FIPS 205, Section 6)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SP_XMSS_H_
#define BOTAN_SP_XMSS_H_

#include <botan/internal/sp_types.h>

#include <optional>

namespace Botan {

class Sphincs_Address;
class Sphincs_Hash_Functions;
class Sphincs_Parameters;

/**
 * @brief FIPS 205, Algorithm 10: xmss_sign
 *
 * This generates a Merkle signature of @p message (i.e. a FORS public key
 * (bottom layer) or an XMSS root node). The Merkle authentication path logic
 * is mostly hidden in treehash_spec. The WOTS signature followed by the Merkle
 * authentication path are stored in @p out_sig.
 * Set @p idx_leaf to `std::nullopt` if no signature is
 * desired.
 *
 * @returns the XMSS public key (i.e. the root of the XMSS merkle tree)
 */
SphincsTreeNode xmss_sign_and_pkgen(StrongSpan<SphincsXmssSignature> out_sig,
                                    const SphincsTreeNode& message,
                                    const SphincsSecretSeed& secret_seed,
                                    Sphincs_Address& wots_addr,
                                    Sphincs_Address& tree_addr,
                                    std::optional<TreeNodeIndex> idx_leaf,
                                    const Sphincs_Parameters& params,
                                    Sphincs_Hash_Functions& hashes);

/**
 * Compute the XMSS public key (root node) of the top-most subtree.
 * Contains logic of FIPS 205, Algorithm 18: slh_keygen_internal
 */
SphincsTreeNode xmss_gen_root(const Sphincs_Parameters& params,
                              const SphincsSecretSeed& secret_seed,
                              Sphincs_Hash_Functions& hashes);

}  // namespace Botan
#endif
