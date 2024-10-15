/*
 * SLH-DSA's Hypertree Logic (FIPS 205, Section 7)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/sp_hypertree.h>

#include <botan/sp_parameters.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_treehash.h>
#include <botan/internal/sp_wots.h>
#include <botan/internal/sp_xmss.h>
#include <botan/internal/stl_util.h>

namespace Botan {

void ht_sign(StrongSpan<SphincsHypertreeSignature> out_sig,
             const SphincsTreeNode& message_to_sign,
             const SphincsSecretSeed& secret_seed,
             XmssTreeIndexInLayer tree_index_in_layer,
             TreeNodeIndex idx_leaf,
             const Sphincs_Parameters& params,
             Sphincs_Hash_Functions& hashes) {
   BOTAN_ASSERT_NOMSG(out_sig.size() == params.ht_signature_bytes());
   BufferStuffer ht_signature(out_sig);

   Sphincs_Address wots_addr(Sphincs_Address_Type::WotsHash);
   wots_addr.set_tree_address(tree_index_in_layer).set_keypair_address(idx_leaf);

   Sphincs_Address tree_addr(Sphincs_Address_Type::HashTree);

   SphincsTreeNode xmss_root;
   for(HypertreeLayerIndex layer_idx(0); layer_idx < params.d(); layer_idx++) {
      // The first XMSS tree signs the message, the others their underlying XMSS tree root
      const SphincsTreeNode& node_to_xmss_sign = (layer_idx == 0U) ? message_to_sign : xmss_root;

      tree_addr.set_layer_address(layer_idx).set_tree_address(tree_index_in_layer);
      wots_addr.copy_subtree_from(tree_addr).set_keypair_address(idx_leaf);

      xmss_root = xmss_sign_and_pkgen(ht_signature.next<SphincsXmssSignature>(params.xmss_signature_bytes()),
                                      node_to_xmss_sign,
                                      secret_seed,
                                      wots_addr,
                                      tree_addr,
                                      idx_leaf,
                                      params,
                                      hashes);

      // Update the indices for the next layer.
      idx_leaf = TreeNodeIndex(tree_index_in_layer.get() & ((1 << params.xmss_tree_height()) - 1));
      tree_index_in_layer = tree_index_in_layer >> params.xmss_tree_height();
   }

   BOTAN_ASSERT_NOMSG(ht_signature.full());
}

bool ht_verify(const SphincsTreeNode& signed_msg,
               StrongSpan<const SphincsHypertreeSignature> ht_sig,
               const SphincsTreeNode& pk_root,
               XmssTreeIndexInLayer tree_index_in_layer,
               TreeNodeIndex idx_leaf,
               const Sphincs_Parameters& params,
               Sphincs_Hash_Functions& hashes) {
   BOTAN_ASSERT_NOMSG(ht_sig.size() == params.ht_signature_bytes());
   BufferSlicer sig_s(ht_sig);

   Sphincs_Address wots_addr(Sphincs_Address_Type::WotsHash);
   Sphincs_Address tree_addr(Sphincs_Address_Type::HashTree);
   Sphincs_Address wots_pk_addr(Sphincs_Address_Type::WotsPublicKeyCompression);

   SphincsTreeNode reconstructed_root(params.n());

   // Each iteration reconstructs the root of one XMSS tree of the hypertree
   for(HypertreeLayerIndex layer_idx(0); layer_idx < params.d(); layer_idx++) {
      // The first XMSS tree signs the message, the others their underlying XMSS tree root
      const SphincsTreeNode& current_root = (layer_idx == 0U) ? signed_msg : reconstructed_root;

      tree_addr.set_layer_address(layer_idx);
      tree_addr.set_tree_address(tree_index_in_layer);

      wots_addr.copy_subtree_from(tree_addr);
      wots_addr.set_keypair_address(idx_leaf);

      wots_pk_addr.copy_keypair_from(wots_addr);

      const auto wots_pk = wots_public_key_from_signature(
         current_root, sig_s.take<WotsSignature>(params.wots_bytes()), wots_addr, params, hashes);

      // Compute the leaf node using the WOTS public key.
      const auto leaf = hashes.T<SphincsTreeNode>(wots_pk_addr, wots_pk);

      // Compute the root node of this subtree.
      compute_root(StrongSpan<SphincsTreeNode>(reconstructed_root),
                   params,
                   hashes,
                   leaf,
                   idx_leaf,
                   0,
                   sig_s.take<SphincsAuthenticationPath>(params.xmss_tree_height() * params.n()),
                   params.xmss_tree_height(),
                   tree_addr);

      // Update the indices for the next layer.
      idx_leaf = TreeNodeIndex(tree_index_in_layer.get() & ((1 << params.xmss_tree_height()) - 1));
      tree_index_in_layer = tree_index_in_layer >> params.xmss_tree_height();
   }

   BOTAN_ASSERT_NOMSG(sig_s.empty());

   // Check if the root node equals the root node in the public key.
   return reconstructed_root == pk_root;
}

}  // namespace Botan
