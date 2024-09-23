/*
* SLH-DSA's XMSS - eXtended Merkle Signature Scheme (FIPS 205, Section 6)
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp_xmss.h>

#include <botan/internal/sp_address.h>
#include <botan/internal/sp_treehash.h>
#include <botan/internal/sp_wots.h>
#include <botan/internal/stl_util.h>
#include <optional>

namespace Botan {

SphincsTreeNode xmss_sign_and_pkgen(StrongSpan<SphincsXmssSignature> out_sig,
                                    const SphincsTreeNode& message,
                                    const SphincsSecretSeed& secret_seed,
                                    Sphincs_Address& wots_addr,
                                    Sphincs_Address& tree_addr,
                                    std::optional<TreeNodeIndex> idx_leaf,
                                    const Sphincs_Parameters& params,
                                    Sphincs_Hash_Functions& hashes) {
   BufferStuffer sig(out_sig);
   auto wots_bytes_s = sig.next<WotsSignature>(params.wots_bytes());
   auto auth_path_s = sig.next<SphincsAuthenticationPath>(sig.remaining_capacity());

   const auto steps = [&]() -> std::vector<WotsHashIndex> {
      // if `idx_leaf` is not set, we don't want to calculate a signature and
      // therefore won't need to bother preparing the chain lengths either.
      if(idx_leaf.has_value()) {
         return chain_lengths(message, params);
      } else {
         return {};
      };
   }();

   Sphincs_Address leaf_addr = Sphincs_Address::as_subtree_from(wots_addr);
   Sphincs_Address pk_addr = Sphincs_Address::as_subtree_from(wots_addr);

   pk_addr.set_type(Sphincs_Address_Type::WotsPublicKeyCompression);

   GenerateLeafFunction xmss_gen_leaf = [&](StrongSpan<SphincsTreeNode> out_root, TreeNodeIndex address_index) {
      wots_sign_and_pkgen(
         wots_bytes_s, out_root, secret_seed, address_index, idx_leaf, steps, leaf_addr, pk_addr, params, hashes);
   };

   SphincsTreeNode next_root(params.n());
   BOTAN_ASSERT_NOMSG(tree_addr.get_type() == Sphincs_Address_Type::HashTree);
   treehash(next_root, auth_path_s, params, hashes, idx_leaf, 0, params.xmss_tree_height(), xmss_gen_leaf, tree_addr);

   return next_root;
}

SphincsTreeNode xmss_gen_root(const Sphincs_Parameters& params,
                              const SphincsSecretSeed& secret_seed,
                              Sphincs_Hash_Functions& hashes) {
   // We do not need the a sig/auth path in key generation, but it simplifies the
   // code to have just one treehash routine that computes both root and path
   // in one function.
   SphincsXmssSignature dummy_sig(params.xmss_tree_height() * params.n() + params.wots_bytes());
   SphincsTreeNode dummy_root(params.n());

   Sphincs_Address top_tree_addr(Sphincs_Address_Type::HashTree);
   Sphincs_Address wots_addr(Sphincs_Address_Type::WotsPublicKeyCompression);

   top_tree_addr.set_layer_address(HypertreeLayerIndex(params.d() - 1));
   wots_addr.set_layer_address(HypertreeLayerIndex(params.d() - 1));

   SphincsTreeNode root =
      xmss_sign_and_pkgen(dummy_sig, dummy_root, secret_seed, wots_addr, top_tree_addr, std::nullopt, params, hashes);

   return root;
}

}  // namespace Botan
