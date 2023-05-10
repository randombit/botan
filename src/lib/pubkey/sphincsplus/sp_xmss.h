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

#include <botan/sp_parameters.h>
#include <botan/internal/sp_types.h>
#include <botan/internal/sp_treehash.h>
#include <botan/internal/sp_wots.h>
#include <botan/internal/sp_address.h>

namespace Botan {

/**
* This generates a Merkle signature of @p root. The Merkle authentication path logic
* is mostly hidden in treehash_spec. The WOTS signature followed by the Merkle
* authentication path are stored in @p out_sig, the new root of the Merkle tree
* is stored in @p out_root.
*/
void xmss_sign(std::span<uint8_t> out_sig,
               std::span<uint8_t> out_root,
               const SphincsHashedMessage& root,
               const SphincsPublicSeed& public_seed,
               const SphincsSecretSeed& secret_seed,
               Sphincs_Address& wots_addr, Sphincs_Address& tree_addr,
               uint32_t idx_leaf, Sphincs_Parameters& params, Sphincs_Hash_Functions& hashes);


/* Compute root node of the top-most subtree. */
void xmss_gen_root(std::span<uint8_t> out_root,
                   Sphincs_Parameters& params, SphincsPublicSeed public_seed, SphincsSecretSeed secret_seed,
                   Sphincs_Hash_Functions& hashes);

}
#endif