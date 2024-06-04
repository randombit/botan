/**
 * Treehash logic used for hash-based signatures
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */
#ifndef BOTAN_TREE_HASH_H_
#define BOTAN_TREE_HASH_H_

#include <botan/exceptn.h>
#include <botan/strong_type.h>
#include <botan/internal/stl_util.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace Botan {

namespace concepts {

template <typename T>
concept tree_node = contiguous_container<T>;

/**
 * @brief An index of a node in a layer.
 *
 * This is a separate index for each layer.
 * The left most node of a layer has the index 0.
 */
template <typename T>
concept tree_node_index = strong_type_with_capability<T, EnableArithmeticWithPlainNumber>;

/**
 * @brief A layer in a Tree.
 *
 * The bottom layer is the layer 0.
 */
template <typename T>
concept tree_layer_index = strong_type_with_capability<T, EnableArithmeticWithPlainNumber>;

template <typename T>
concept strong_span = is_strong_span_v<T>;

/**
 * @brief An adress in a Tree.
 */
template <typename T, typename TreeLayerIndex, typename TreeNodeIndex>
concept tree_address = requires(T a, TreeLayerIndex tree_layer, TreeNodeIndex tree_index) {
   requires tree_layer_index<TreeLayerIndex>;
   requires tree_node_index<TreeNodeIndex>;
   { a.set_address(tree_layer, tree_index) };
};

template <typename T, typename NodeIdx, typename LayerIdx, typename Address, typename NodeSS>
concept tree_hash_node_pair = concepts::tree_node_index<NodeIdx> && concepts::tree_layer_index<LayerIdx> &&
                              concepts::tree_address<Address, LayerIdx, NodeIdx> && concepts::strong_span<NodeSS> &&
                              requires(T func, NodeSS out, const Address& address, NodeSS a, NodeSS b) {
                                 { func(out, address, a, b) };
                              };

template <typename T, typename NodeIdx, typename LayerIdx, typename Address, typename NodeSS>
concept tree_gen_leaf = concepts::tree_node_index<NodeIdx> && concepts::tree_layer_index<LayerIdx> &&
                        concepts::tree_address<Address, LayerIdx, NodeIdx> && concepts::strong_span<NodeSS> &&
                        requires(T func, NodeSS out, const Address& address) {
                           { func(out, address) };
                        };

}  // namespace concepts

/**
 * @brief Treehash logic to build up a merkle hash tree.
 *
 * Computes the root of the merkle tree.
 * Can also output an authentication path necessary for a hash based signature.
 *
 * Given the following tree:
 *  Layer:
 *     2       7R
 *            /  \
 *     1    3X    6A
 *         / \    / \
 *     0  1X  2A 4   5
 *
 * The treehash logic traverses the tree (Post-order traversal), i.e., the nodes are
 * discovered in order 1,2,3,...,7. If we want to create a signature using leaf node 1,
 * the authentication path is (Node 2, Node 6), since we need those to compute the
 * root.
 *
 * @param out_root An output buffer to store the root node in (size: node_size ).
 * @param out_auth_path Optional buffer to store the authentication path in (size: node_size * total_tree_height).
 * @param leaf_idx The optional index of the leaf used to sign in the bottom tree layer beginning with index 0.
 *                 nullopt if no node is signed, so we need no auth path.
 * @param node_size The size of each node in the tree.
 * @param total_tree_height The hight of the merkle tree to construct.
 * @param idx_offset If we compute a subtree this marks the index of the leftmost leaf node in the bottom layer
 * @param node_pair_hash The function to process two child nodes to compute their parent node.
 * @param gen_leaf The logic to create a leaf node given the address in the tree. Probably this function
 *                 creates a one-time/few-time-signature's public key which is hashed to be the leaf node.
 * @param tree_address The address that is passed to gen_leaf or node_pair hash. This function will update the
 *                     address accordings to the currently processed node. This object may contain further
 *                     algorithm specific information, like the position of this merkle tree in a hypertree.
 */
template <concepts::contiguous_strong_type TreeNode,
          concepts::strong_span AuthPathSS,
          concepts::tree_node_index TreeNodeIndex,
          concepts::tree_layer_index TreeLayerIndex,
          typename Address>
   requires concepts::tree_address<Address, TreeLayerIndex, TreeNodeIndex>
inline void treehash(
   StrongSpan<TreeNode> out_root,
   std::optional<AuthPathSS> out_auth_path,
   std::optional<TreeNodeIndex> leaf_idx,
   size_t node_size,
   TreeLayerIndex total_tree_height,
   uint32_t idx_offset,
   concepts::tree_hash_node_pair<TreeNodeIndex, TreeLayerIndex, Address, StrongSpan<TreeNode>> auto node_pair_hash,
   concepts::tree_gen_leaf<TreeNodeIndex, TreeLayerIndex, Address, StrongSpan<TreeNode>> auto gen_leaf,
   Address& tree_address) {
   BOTAN_ASSERT_NOMSG(out_root.size() == node_size);
   BOTAN_ASSERT(out_auth_path.has_value() == leaf_idx.has_value(),
                "Both leaf index and auth path buffer is given or neither.");
   const bool is_signing = leaf_idx.has_value();
   BOTAN_ASSERT_NOMSG(!is_signing || out_auth_path.value().size() == node_size * total_tree_height.get());

   const TreeNodeIndex max_idx(uint32_t((1 << total_tree_height.get()) - 1));

   std::vector<TreeNode> last_visited_left_child_at_layer(total_tree_height.get(), TreeNode(node_size));

   TreeNode current_node(node_size);  // Current logical node

   // Traverse the tree from the left-most leaf, matching siblings and up until
   // the root (Post-order traversal). Collect the adjacent nodes to build
   // the authentication path along the way.
   for(TreeNodeIndex idx(0); true; ++idx) {
      tree_address.set_address(TreeLayerIndex(0), idx + idx_offset);
      gen_leaf(StrongSpan<TreeNode>(current_node), tree_address);

      // Now combine the freshly generated right node with previously generated
      // left ones
      uint32_t internal_idx_offset = idx_offset;
      TreeNodeIndex internal_idx = idx;
      auto internal_leaf = leaf_idx;

      for(TreeLayerIndex h(0); true; ++h) {
         // Check if we hit the top of the tree
         if(h == total_tree_height) {
            copy_mem(out_root, current_node);
            return;
         }

         // Check if the node we have is a part of the authentication path; if
         // it is, write it out. The XOR sum of both nodes (at internal_idx and internal_leaf)
         // is 1 iff they have the same parent node in the FORS tree
         if(is_signing && (internal_idx ^ internal_leaf.value()) == 0x01U) {
            auto auth_path_location = out_auth_path.value().get().subspan(h.get() * node_size, node_size);
            copy_mem(auth_path_location, current_node);
         }

         // Check if we're at a left child; if so, stop going up the tree
         // Exception: if we've reached the end of the tree, keep on going (so
         // we combine the last 4 nodes into the one root node in two more
         // iterations)
         if((internal_idx & 1) == 0U && idx < max_idx) {
            // We've hit a left child; save the current for when we get the
            // corresponding right child.
            copy_mem(last_visited_left_child_at_layer.at(h.get()), current_node);
            break;
         }

         // Ok, we're at a right node. Now combine the left and right logical
         // nodes together.

         // Set the address of the node we're creating.
         internal_idx_offset /= 2;
         tree_address.set_address(h + 1, internal_idx / 2 + internal_idx_offset);

         node_pair_hash(current_node, tree_address, last_visited_left_child_at_layer.at(h.get()), current_node);

         internal_idx /= 2;
         if(internal_leaf.has_value()) {
            internal_leaf.value() /= 2;
         }
      }
   }
}

/**
 * @brief Uses an authentication path and a leaf node to reconstruct the root node
 * of a merkle tree.
 *
 * @param out_root A output buffer for the root node of the merkle tree.
 * @param authentication_path The authentication path in one buffer (concatenated nodes).
 * @param leaf_idx The index of the leaf used to sig in the bottom layer beginning with 0.
 * @param leaf The leaf node used to sig.
 * @param node_size The size of each node in the tree.
 * @param total_tree_height The hight of the merkle tree to construct.
 * @param idx_offset If we compute a subtree this marks the index of the leftmost leaf node in the bottom layer.
 * @param node_pair_hash The function to process two child nodes to compute their parent node.
 * @param tree_address The address that is passed to node_pair hash. This function will update the
 *                     address accordings to the currently processed node. This object may contain further
 *                     algorithm specific information, like the position of this merkle tree in a hypertree.
 */
template <concepts::contiguous_strong_type TreeNode,
          concepts::strong_span AuthPathSS,
          concepts::tree_node_index TreeNodeIndex,
          concepts::tree_layer_index TreeLayerIndex,
          typename Address>
   requires concepts::tree_address<Address, TreeLayerIndex, TreeNodeIndex>
inline void compute_root(
   StrongSpan<TreeNode> out_root,
   AuthPathSS authentication_path,
   TreeNodeIndex leaf_idx,
   StrongSpan<const TreeNode> leaf,
   size_t node_size,
   TreeLayerIndex total_tree_height,
   uint32_t idx_offset,
   concepts::tree_hash_node_pair<TreeNodeIndex, TreeLayerIndex, Address, StrongSpan<TreeNode>> auto node_pair_hash,
   Address& tree_address) {
   BOTAN_ASSERT_NOMSG(out_root.size() == node_size);
   BOTAN_ASSERT_NOMSG(authentication_path.size() == node_size * static_cast<size_t>(total_tree_height.get()));
   BOTAN_ASSERT_NOMSG(leaf.size() == node_size);

   // Use the `out` parameter as intermediate buffer for left/right nodes
   // while traversing the tree.
   copy_mem(out_root, leaf);

   // Views into either `auth_path` or `out` depending on the tree location.
   StrongSpan<const TreeNode> left;
   StrongSpan<const TreeNode> right;

   BufferSlicer auth_path(authentication_path);

   // The leaf is put in the left or right buffer, depending on its indexes parity.
   // Same for the first node of the authentication path

   for(TreeLayerIndex i(0); i < total_tree_height; i++) {
      // The input of the hash function takes the current node and the node
      // given in the authentication path. If the current node is a right node
      // in the tree (i.e. its leaf index is uneven) the hash function inputs
      // must be swapped.
      left = out_root;
      right = auth_path.take<TreeNode>(node_size);

      if((leaf_idx & 1) == 1U) {
         std::swap(left, right);
      }

      leaf_idx /= 2;
      idx_offset /= 2;
      tree_address.set_address(i + 1, leaf_idx + idx_offset);

      node_pair_hash(out_root, tree_address, left, right);
   }

   BOTAN_ASSERT_NOMSG(auth_path.empty());
}
}  // namespace Botan

#endif  // BOTAN_TREE_HASH_H_
