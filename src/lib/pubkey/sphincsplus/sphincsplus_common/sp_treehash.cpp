/*
* SLH-DSA treehash logic
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/sp_treehash.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_hash.h>

namespace Botan {

void treehash(StrongSpan<SphincsTreeNode> out_root,
              StrongSpan<SphincsAuthenticationPath> out_auth_path,
              const Sphincs_Parameters& params,
              Sphincs_Hash_Functions& hashes,
              std::optional<TreeNodeIndex> leaf_idx,
              uint32_t idx_offset,
              uint32_t total_tree_height,
              const GenerateLeavesFunction& gen_leaves,
              Sphincs_Address& tree_address) {
   BOTAN_ASSERT_NOMSG(out_root.size() == params.n());
   BOTAN_ASSERT_NOMSG(out_auth_path.size() == params.n() * total_tree_height);
   BOTAN_ASSERT_NOMSG(total_tree_height < 32);

   const TreeNodeIndex max_idx((uint32_t(1) << total_tree_height) - 1);
   // Not has_value() || value(), which GCC may compile to test the payload first
   BOTAN_ASSERT_NOMSG(leaf_idx.value_or(TreeNodeIndex(0)) <= max_idx);

   const size_t n = params.n();

   /* Traverse the tree from the left-most node, matching siblings and up until
   * the root (Post-order traversal). Collect the adjacent nodes (A) to build
   * the authentication path (X) along the way.
   *
   *         7R
   *        /  \
   *      3X    6A
   *     / \    / \
   *   1X  2A  4   5
   *
   * push() takes the next node of layer h in this order, combining it with the
   * left siblings saved on the stack until reaching a left child or the root.
   */
   std::vector<uint8_t> stack(total_tree_height * n);

   const auto push = [&](std::span<uint8_t> node, uint32_t h, uint32_t idx) {
      for(;; ++h, idx /= 2) {
         // Check if we hit the top of the tree
         if(h == total_tree_height) {
            copy_mem(out_root, node);
            return;
         }

         // Check if the node we have is a part of the authentication path; if
         // it is, write it out. The XOR sum of both nodes (at idx and the signed
         // leaf's ancestor) is 1 iff they have the same parent node in the tree
         if(leaf_idx.has_value() && (idx ^ (leaf_idx->get() >> h)) == 0x01U) {
            copy_mem(out_auth_path.get().subspan(h * n, n), node);
         }

         // At this point we know that we'll need to use the stack. Get a
         // reference to the correct location.
         const auto stack_location = std::span(stack).subspan(h * n, n);

         // Check if we're at a left child; if so, save it for when we get the
         // corresponding right child, and stop going up the stack
         if((idx & 1) == 0) {
            copy_mem(stack_location, node);
            return;
         }

         // Ok, we're at a right node. Now combine the left and right logical
         // nodes together, setting the address of the node we're creating.
         tree_address.set_tree_height(TreeLayerIndex(h + 1));
         tree_address.set_tree_index(TreeNodeIndex(idx / 2 + (idx_offset >> (h + 1))));
         hashes.T(node, tree_address, stack_location, node);
      }
   };

   // Leaves are created in chunks, and the lower layers of each chunk hashed
   // layer by layer, to enable batched hashing. Both the chunk size and the
   // leaf count are powers of two, so chunks are always full. Once a layer is
   // too narrow to batch well, its nodes go through the stack one at a time.
   constexpr uint32_t max_chunk_height = 7;
   constexpr uint32_t min_batch = 16;

   const uint32_t chunk_height = std::min(total_tree_height, max_chunk_height);
   const uint32_t leaves_per_chunk = uint32_t(1) << chunk_height;

   // Layers of a chunk alternate between these, as each fits half the last
   std::vector<uint8_t> layer_bufs(leaves_per_chunk * n + leaves_per_chunk / 2 * n);
   const auto layer_buf_a = std::span(layer_bufs).first(leaves_per_chunk * n);
   const auto layer_buf_b = std::span(layer_bufs).subspan(leaves_per_chunk * n);

   std::vector<Sphincs_Address> addrs;
   std::vector<std::span<uint8_t>> parents;
   std::vector<std::span<const uint8_t>> children;

   const uint32_t chunks = uint32_t(1) << (total_tree_height - chunk_height);
   for(uint32_t chunk = 0; chunk != chunks; ++chunk) {
      const uint32_t first_leaf = chunk * leaves_per_chunk;
      auto layer = layer_buf_a;
      auto next_layer = layer_buf_b;

      gen_leaves(layer, TreeNodeIndex(first_leaf + idx_offset), leaves_per_chunk);

      // Within a chunk, auth path nodes only come from the chunk with the leaf
      const bool chunk_has_leaf = leaf_idx.has_value() && (leaf_idx->get() >> chunk_height) == chunk;

      uint32_t h = 0;
      uint32_t width = leaves_per_chunk;

      for(; h != chunk_height && width / 2 >= min_batch; ++h, width /= 2) {
         const uint32_t first = first_leaf >> h;

         if(chunk_has_leaf) {
            const uint32_t sibling = (leaf_idx->get() >> h) ^ 1;
            copy_mem(out_auth_path.get().subspan(h * n, n), layer.subspan((sibling - first) * n, n));
         }

         const uint32_t count = width / 2;
         addrs.assign(count, tree_address);
         parents.resize(count);
         children.resize(count);
         for(uint32_t i = 0; i != count; ++i) {
            addrs[i]
               .set_tree_height(TreeLayerIndex(h + 1))
               .set_tree_index(TreeNodeIndex((first >> 1) + i + (idx_offset >> (h + 1))));
            parents[i] = next_layer.subspan(i * n, n);
            children[i] = layer.subspan(2 * i * n, 2 * n);
         }

         hashes.T_batch(parents, addrs, children);
         std::swap(layer, next_layer);
      }

      for(uint32_t i = 0; i != width; ++i) {
         push(layer.subspan(i * n, n), h, (first_leaf >> h) + i);
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
