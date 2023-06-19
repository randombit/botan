/*
 * Sphincs+ XMSS logic
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_XMSS_H_
#define BOTAN_SP_XMSS_H_

#include <botan/internal/sp_types.h>

#include <optional>

namespace Botan {

class Sphincs_Address;
class Sphincs_Hash_Functions;
class Sphincs_Parameters;

/**
* This generates a Merkle signature of @p root. The Merkle authentication path logic
* is mostly hidden in treehash_spec. The WOTS signature followed by the Merkle
* authentication path are stored in @p out_sig, the new root of the Merkle tree
* is stored in @p out_root. Set @p idx_leaf to `std::nullopt` if no signature is
* desired.
*/
SphincsTreeNode xmss_sign_and_pkgen(StrongSpan<SphincsXmssSignature> out_sig,
                                    const SphincsTreeNode& root,
                                    const SphincsSecretSeed& secret_seed,
                                    Sphincs_Address& wots_addr,
                                    Sphincs_Address& tree_addr,
                                    std::optional<TreeNodeIndex> idx_leaf,
                                    const Sphincs_Parameters& params,
                                    Sphincs_Hash_Functions& hashes);

/* Compute root node of the top-most subtree. */
SphincsTreeNode xmss_gen_root(const Sphincs_Parameters& params,
                              const SphincsSecretSeed& secret_seed,
                              Sphincs_Hash_Functions& hashes);

}  // namespace Botan
#endif
