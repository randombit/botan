/*
* Sphincs+ treehash logic
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/sp_treehash.h>

namespace Botan
{

void
treehash_spec(std::span<uint8_t> out_root,
              std::span<uint8_t> out_auth_path,
              const Sphincs_Parameters& params,
              Sphincs_Hash_Functions& hashes,
              const SphincsPublicSeed& pub_seed,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              GenerateLeafFunction gen_leaf,
              Sphincs_Address& tree_address)
   {
   BOTAN_ASSERT_NOMSG(out_root.size() == params.n());
   BOTAN_ASSERT_NOMSG(out_auth_path.size() == params.n() * tree_height);
   const uint32_t max_idx = uint32_t((1 << tree_height) - 1);

   std::vector<uint8_t> stack(tree_height * params.n());
   secure_vector<uint8_t> current_node(params.n()); // Current logical node

   // Traverse the tree from the left-most leaf, matching siblings and up until
   // the root (Post-order traversal). Collect the adjacent nodes (A) to build
   // the authentication path (X) along the way.
   //
   //        7R
   //       /  \
   //     3X    6A
   //    / \    / \
   //  1X  2A  4   5
   for (uint32_t idx = 0; true; ++idx)
      {
      tree_address.set_tree_height(0);
      gen_leaf(current_node, idx + idx_offset);

      // Now combine the freshly generated right node with previously generated
      // left ones
      uint32_t internal_idx_offset = idx_offset;
      uint32_t internal_idx = idx;
      uint32_t internal_leaf = leaf_idx;

      for (uint32_t h = 0; true; ++h, internal_idx /= 2, internal_leaf /= 2)
         {
         // Check if we hit the top of the tree
         if (h == tree_height)
            {
            std::copy(current_node.begin(), current_node.end(), out_root.begin());
            return;
            }

         // Check if the node we have is a part of the authentication path; if
         // it is, write it out. The XOR sum of both nodes (at internal_idx and internal_leaf)
         // is 1 iff they have the same parent node in the FORS tree
         if ((internal_idx ^ internal_leaf) == 0x01) {
            auto auth_path_location = std::span(out_auth_path).subspan(h * params.n(), params.n());
            std::copy(current_node.begin(), current_node.end(), auth_path_location.begin());
         }

         // At this point we know that we'll need to use the stack. Get a
         // reference to the correct location.
         auto stack_location = std::span(stack).subspan(h * params.n(), params.n());

         // Check if we're at a left child; if so, stop going up the stack
         // Exception: if we've reached the end of the tree, keep on going (so
         // we combine the last 4 nodes into the one root node in two more
         // iterations)
         if ((internal_idx & 1) == 0 && idx < max_idx)
            {
            // We've hit a left child; save the current for when we get the
            // corresponding right child.
            std::copy(current_node.begin(), current_node.end(), stack_location.begin());
            break;
            }

         // Ok, we're at a right node. Now combine the left and right logical
         // nodes together.

         // Set the address of the node we're creating.
         internal_idx_offset /= 2;
         tree_address.set_tree_height(h + 1);
         tree_address.set_tree_index(internal_idx/2 + internal_idx_offset);

         hashes.T(current_node, pub_seed, tree_address, stack_location, current_node);
         }
      }
      std::copy(stack.begin(), stack.begin() + params.n(), out_root.begin());
   }

void compute_root_spec(std::span<uint8_t> out,
                       const Sphincs_Parameters& params,
                       const SphincsPublicSeed& public_seed,
                       Sphincs_Hash_Functions& hashes,
                       const std::vector<uint8_t>& leaf, // Leaf
                       uint32_t leaf_idx, uint32_t idx_offset,
                       std::span<const uint8_t> auth_path,
                       uint32_t tree_height,
                       Sphincs_Address& tree_address)
   {
   BOTAN_ASSERT_NOMSG(out.size() == params.n());
   BOTAN_ASSERT_NOMSG(auth_path.size() == params.n() * tree_height);

   // Input for the hash function. Format: [left tree node] || [right tree node]
   std::vector<uint8_t> buffer(2 * params.n());
   auto left_buffer = std::span(buffer).subspan(0, params.n());
   auto right_buffer = std::span(buffer).subspan(params.n(), params.n());

   auto auth_path_location = auth_path.subspan(0, params.n());

   // The leaf is put in the left or right buffer, depending on its indexes parity.
   // Same for the first node of the authentication path
   if(leaf_idx % 2 == 0)
      {
      std::copy(leaf.begin(), leaf.end(),left_buffer.begin());
      std::copy(auth_path_location.begin(), auth_path_location.end(), right_buffer.begin());
      }
   else
      {
      std::copy(leaf.begin(), leaf.end(),right_buffer.begin());
      std::copy(auth_path_location.begin(), auth_path_location.end(), left_buffer.begin());
      }

   for (uint32_t i = 0; i < tree_height - 1; i++)
      {
      leaf_idx /= 2;
      idx_offset /= 2;
      tree_address.set_tree_height(i+1).set_tree_index(leaf_idx + idx_offset);

      auth_path_location = auth_path.subspan( (i+1) * params.n(), params.n() );

      // Perform the hash operation. Depending on node's index in the current layer the output is either written
      // to the left or right part of the buffer. The next node of the authentication path is written at the other
      // side. This logic already prepares the buffer for the next operation in the next tree layer.
      if (leaf_idx & 1)
         {
            hashes.T(right_buffer, public_seed, tree_address, left_buffer, right_buffer);
            std::copy(auth_path_location.begin(), auth_path_location.end(), left_buffer.begin());
         }
      else
         {
         hashes.T(left_buffer, public_seed, tree_address, left_buffer, right_buffer);
         std::copy(auth_path_location.begin(), auth_path_location.end(), right_buffer.begin());
         }
      }
   // The last hash iteration is performed outside the loop since no further nodes must be prepared at this point.
   leaf_idx /= 2;
   idx_offset /= 2;
   tree_address.set_tree_height(tree_height).set_tree_index(leaf_idx + idx_offset);
   hashes.T(out, public_seed, tree_address, left_buffer, right_buffer);
   }

}
