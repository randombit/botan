/*
 * Sphincs+ treehash logic
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_TREEHASH_H_
#define BOTAN_SP_TREEHASH_H_

#include <botan/sp_parameters.h>
#include <botan/internal/sp_types.h>

#include <functional>
#include <optional>

namespace Botan {

class Sphincs_Address;
class Sphincs_Hash_Functions;

using GenerateLeafFunction = std::function<void(StrongSpan<SphincsTreeNode> /* leaf out parameter */, TreeNodeIndex)>;

/**
 * Implements a generic Merkle tree hash. Will be used for both FORS and XMSS
 * signatures.
 * @p gen_leaf is used to create leaf nodes in the respective trees.
 * Additionally XMSS uses the gen_leaf logic to store the WOTS Signature in the
 * main Sphincs+ signature. The @p leaf_idx is the index of leaf to sign. If
 * only the root node must be computed (without a signature), the @p leaf_idx is
 * set to std::nullopt.
 */
BOTAN_TEST_API void treehash(StrongSpan<SphincsTreeNode> out_root,
                             StrongSpan<SphincsAuthenticationPath> out_auth_path,
                             const Sphincs_Parameters& params,
                             Sphincs_Hash_Functions& hashes,
                             std::optional<TreeNodeIndex> leaf_idx,
                             uint32_t idx_offset,
                             uint32_t tree_height,
                             const GenerateLeafFunction& gen_leaf,
                             Sphincs_Address& tree_address);

/**
 * Using a leaf node and the authentication path (neighbor nodes on the way from
 * leaf to root), computes the the root node of the respective tree. This
 * function is generic and used by FORS and XMSS in the SPHINCS+ verification
 * logic.
 */
BOTAN_TEST_API void compute_root(StrongSpan<SphincsTreeNode> out,
                                 const Sphincs_Parameters& params,
                                 Sphincs_Hash_Functions& hashes,
                                 const SphincsTreeNode& leaf,
                                 TreeNodeIndex leaf_idx,
                                 uint32_t idx_offset,
                                 StrongSpan<const SphincsAuthenticationPath> authentication_path,
                                 uint32_t tree_height,
                                 Sphincs_Address& tree_address);

}  // namespace Botan

#endif
