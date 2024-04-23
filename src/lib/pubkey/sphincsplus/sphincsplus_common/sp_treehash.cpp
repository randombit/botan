/*
* Sphincs+ treehash logic
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/sp_treehash.h>

#include <botan/internal/sp_address.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/stl_util.h>

namespace Botan {

void treehash(StrongSpan<SphincsTreeNode> out_root,
              StrongSpan<SphincsAuthenticationPath> out_auth_path,
              const Sphincs_Parameters& params,
              Sphincs_Hash_Functions& hashes,
              std::optional<TreeNodeIndex> leaf_idx,
              uint32_t idx_offset,
              uint32_t total_tree_height,
              const GenerateLeafFunction& gen_leaf,
              Sphincs_Address& tree_address) {
   BOTAN_ASSERT_NOMSG(out_root.size() == params.n());
   BOTAN_ASSERT_NOMSG(out_auth_path.size() == params.n() * total_tree_height);

   const TreeNodeIndex max_idx(uint32_t((1 << total_tree_height) - 1));

   std::vector<uint8_t> stack(total_tree_height * params.n());
   SphincsTreeNode current_node(params.n());  // Current logical node

   /* Traverse the tree from the left-most leaf, matching siblings and up until
   * the root (Post-order traversal). Collect the adjacent nodes (A) to build
   * the authentication path (X) along the way.
   *
   *         7R
   *        /  \
   *      3X    6A
   *     / \    / \
   *   1X  2A  4   5
   */
   for(TreeNodeIndex idx(0); true; ++idx) {
      tree_address.set_tree_height(TreeLayerIndex(0));
      gen_leaf(current_node, idx + idx_offset);

      // Now combine the freshly generated right node with previously generated
      // left ones
      uint32_t internal_idx_offset = idx_offset;
      TreeNodeIndex internal_idx = idx;
      auto internal_leaf = leaf_idx;

      for(TreeLayerIndex h(0); true; ++h) {
         // Check if we hit the top of the tree
         if(h.get() == total_tree_height) {
            copy_mem(out_root, current_node);
            return;
         }

         // Check if the node we have is a part of the authentication path; if
         // it is, write it out. The XOR sum of both nodes (at internal_idx and internal_leaf)
         // is 1 iff they have the same parent node in the FORS tree
         if(internal_leaf.has_value() && (internal_idx ^ internal_leaf.value()) == 0x01U) {
            auto auth_path_location = out_auth_path.get().subspan(h.get() * params.n(), params.n());
            copy_mem(auth_path_location, current_node);
         }

         // At this point we know that we'll need to use the stack. Get a
         // reference to the correct location.
         auto stack_location = std::span(stack).subspan(h.get() * params.n(), params.n());

         // Check if we're at a left child; if so, stop going up the stack
         // Exception: if we've reached the end of the tree, keep on going (so
         // we combine the last 4 nodes into the one root node in two more
         // iterations)
         if((internal_idx & 1) == 0U && idx < max_idx) {
            // We've hit a left child; save the current for when we get the
            // corresponding right child.
            copy_mem(stack_location, current_node);
            break;
         }

         // Ok, we're at a right node. Now combine the left and right logical
         // nodes together.

         // Set the address of the node we're creating.
         internal_idx_offset /= 2;
         tree_address.set_tree_height(h + 1);
         tree_address.set_tree_index(internal_idx / 2 + internal_idx_offset);

         hashes.T(current_node, tree_address, stack_location, current_node);

         internal_idx /= 2;
         if(internal_leaf.has_value()) {
            internal_leaf.value() /= 2;
         }
      }
   }
}

void compute_root(StrongSpan<SphincsTreeNode> out,
                  const Sphincs_Parameters& params,
                  Sphincs_Hash_Functions& hashes,
                  const SphincsTreeNode& leaf,
                  TreeNodeIndex leaf_idx,
                  uint32_t idx_offset,
                  StrongSpan<const SphincsAuthenticationPath> authentication_path,
                  uint32_t total_tree_height,
                  Sphincs_Address& tree_address) {
   BOTAN_ASSERT_NOMSG(out.size() == params.n());
   BOTAN_ASSERT_NOMSG(authentication_path.size() == params.n() * total_tree_height);
   BOTAN_ASSERT_NOMSG(leaf.size() == params.n());

   // Use the `out` parameter as intermediate buffer for left/right nodes
   // while traversing the tree.
   copy_mem(out, leaf);

   // Views into either `auth_path` or `out` depending on the tree location.
   StrongSpan<const SphincsTreeNode> left;
   StrongSpan<const SphincsTreeNode> right;

   BufferSlicer auth_path(authentication_path);

   // The leaf is put in the left or right buffer, depending on its indexes parity.
   // Same for the first node of the authentication path

   for(TreeLayerIndex i(0); i < total_tree_height; i++) {
      // The input of the hash function takes the current node and the node
      // given in the authentication path. If the current node is a right node
      // in the tree (i.e. its leaf index is uneven) the hash function inputs
      // must be swapped.
      left = out;
      right = auth_path.take<SphincsTreeNode>(params.n());

      if((leaf_idx & 1) == 1U) {
         std::swap(left, right);
      }

      leaf_idx /= 2;
      idx_offset /= 2;
      tree_address.set_tree_height(i + 1).set_tree_index(leaf_idx + idx_offset);

      hashes.T(out, tree_address, left, right);
   }

   BOTAN_ASSERT_NOMSG(auth_path.empty());
}

}  // namespace Botan
