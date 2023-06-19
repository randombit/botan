/*
 * Sphincs+ hypertree logic
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_HYPERTREE_H_
#define BOTAN_SP_HYPERTREE_H_

#include <botan/internal/sp_types.h>

namespace Botan {

class Sphincs_Address;
class Sphincs_Hash_Functions;
class Sphincs_Parameters;

/**
 * Creates a SPHINCS+ XMSS hypertree signature of @p message_to_sign. The signature is written
 * into the buffer defined by @p out_sig. @p tree_index_in_layer and @p idx_leaf define which
 * XMSS tree of the hypertree and which leaf of this XMSS tree is used for signing.
 */
void ht_sign(StrongSpan<SphincsHypertreeSignature> out_sig,
             const SphincsTreeNode& message_to_sign,
             const SphincsSecretSeed& secret_seed,
             XmssTreeIndexInLayer tree_index_in_layer,
             TreeNodeIndex idx_leaf,
             const Sphincs_Parameters& params,
             Sphincs_Hash_Functions& hashes);

/**
 * Given a message @p signed_msg the SPHINCS+ XMSS hypertree is reconstructed
 * using a hypertree signature @p ht_sig. @p tree_index_in_layer and @p idx_leaf
 * define which XMSS tree of the hypertree and which leaf of this XMSS tree was
 * used for signing.
 *
 * @returns true iff the top-most reconstructed root equals @p pk_root
 */
bool ht_verify(const SphincsTreeNode& signed_msg,
               StrongSpan<const SphincsHypertreeSignature> ht_sig,
               const SphincsTreeNode& pk_root,
               XmssTreeIndexInLayer tree_index_in_layer,
               TreeNodeIndex idx_leaf,
               const Sphincs_Parameters& params,
               Sphincs_Hash_Functions& hashes);

}  // namespace Botan
#endif
