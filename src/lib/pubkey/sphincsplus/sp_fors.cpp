/*
 * FORS - Forest of Random Subsets
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/


#include "botan/internal/sp_hash.h"
#include "sp_types.h"
#include <botan/sp_parameters.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_fors.h>
#include <botan/internal/mgf1.h>

#include <botan/hash.h>

namespace Botan
{

ForsIndices fors_message_to_indices(std::span<const uint8_t> message, const Sphincs_Parameters& params)
   {
   BOTAN_ASSERT_NOMSG((message.size() * 8) >= (params.k() * params.a()));

   ForsIndices indices(params.k());

   unsigned int offset = 0;

   for(auto& idx : indices)
      {
      for(unsigned int i = 0; i < params.a(); ++i, ++offset)
         {
         idx ^= ((message[offset >> 3] >> (offset & 0x7)) & 0x1) << i;
         }
      }

   return indices;
   }

using GenerateLeafFunction =
   std::function<void(std::span<uint8_t> /* leaf out parameter */,
                      const Sphincs_Parameters&,
                      const SphincsSecretSeed&,
                      const SphincsPublicSeed&,
                      uint32_t /* address index */,
                      Sphincs_Address&,
                      Sphincs_Hash_Functions&)>;

void fors_gen_leafx1(std::span<uint8_t> out,
                     const Sphincs_Parameters& params,
                     const SphincsSecretSeed& secret_seed,
                     const SphincsPublicSeed& public_seed,
                     uint32_t address_index,
                     Sphincs_Address& fors_leaf_address,
                     Sphincs_Hash_Functions& hashes)
   {
   // TODO: Check if params is always unused
   BOTAN_UNUSED(params);
   fors_leaf_address.set_tree_index(address_index);
   fors_leaf_address.set_type(Sphincs_Address_Type::ForsKeyGeneration);

   // Storing the intermediate output in the out memory
   hashes.PRF(out, public_seed, secret_seed, fors_leaf_address);

   fors_leaf_address.set_type(Sphincs_Address_Type::ForsTree);
   hashes.F(out, public_seed, fors_leaf_address, out);
   }


void compute_root_spec(std::span<uint8_t> out,
                       const Sphincs_Parameters& params,
                       const SphincsPublicSeed& public_seed,
                       Sphincs_Hash_Functions& hashes,
                       const std::vector<uint8_t> leaf, // Leaf
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

   auto auth_path_location = std::span(auth_path).subspan(0, params.n());

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

      auth_path_location = std::span(auth_path).subspan( (i+1) * params.n(), params.n() );

      // Perform the hash operation. Depending on node's index in the current layer the output is either written
      // to the left or right part of the buffer. The next node of the authentication path is written at the other
      // side. This logic already prepares the buffer for the next operation in the next tree layer.
      if (leaf_idx & 1)
         {
            hashes.H(right_buffer, public_seed, tree_address, left_buffer, right_buffer);
            std::copy(auth_path_location.begin(), auth_path_location.end(), left_buffer.begin());
         }
      else
         {
         hashes.H(left_buffer, public_seed, tree_address, left_buffer, right_buffer);
         std::copy(auth_path_location.begin(), auth_path_location.end(), right_buffer.begin());
         }
      }
   // The last hash iteration is performed outside the loop since no further nodes must be prepared at this point.
   leaf_idx /= 2;
   idx_offset /= 2;
   tree_address.set_tree_height(tree_height).set_tree_index(leaf_idx + idx_offset);
   hashes.H(out, public_seed, tree_address, left_buffer, right_buffer);
   //hashes.F(out, public_seed, tree_address, buffer);
   }

void
treehashSpec(std::span<uint8_t> out_root,
             std::span<uint8_t> out_auth_path,
             const Sphincs_Parameters& params,
             Sphincs_Hash_Functions& hashes,
             const SphincsSecretSeed& sk_seed, const SphincsPublicSeed& pub_seed,
             uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
             GenerateLeafFunction gen_leaf,
             Sphincs_Address& tree_address)
   {
   BOTAN_ASSERT_NOMSG(out_root.size() == params.n());
   BOTAN_ASSERT_NOMSG(out_auth_path.size() == params.n() * tree_height);
   const uint32_t max_idx = uint32_t((1 << tree_height) - 1);

   std::vector<uint8_t> stack(tree_height * params.n());
   std::vector<uint8_t> current_node(params.n()); // Current logical node

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
      gen_leaf(current_node, params, sk_seed, pub_seed, idx + idx_offset, tree_address, hashes);

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

         hashes.H(current_node, pub_seed, tree_address, stack_location, current_node);
         }
      }
      std::copy(stack.begin(), stack.begin() + params.n(), out_root.begin());
   }

std::pair<ForsPublicKey, ForsSignature> fors_sign(const SphincsHashedMessage& hashed_message,
                                                  const SphincsSecretSeed& secret_seed,
                                                  const SphincsPublicSeed& public_seed,
                                                  const Sphincs_Address& address,
                                                  const Sphincs_Parameters& params,
                                                  Sphincs_Hash_Functions& hashes)
   {
   const auto indices = fors_message_to_indices(hashed_message, params);

   auto fors_tree_addr =
      Sphincs_Address::as_keypair_from(address)
         .set_type(Sphincs_Address::ForsTree);

   auto fors_pk_addr =
      Sphincs_Address::as_keypair_from(address)
         .set_type(Sphincs_Address::ForsTreeRootsCompression);

   ForsSignature signature((params.a() + 1) * params.k()* params.n());

   std::vector<uint8_t> roots(params.k() * params.n());

   // For each of the k FORS subtrees: Compute the secret leaf, the authentication path
   // and the trees' root and append the signature respectively
   for(size_t i = 0; i < params.k(); ++i)
      {
      uint32_t idx_offset = i * (1 << params.a());

      // Compute the secret leaf given by the chunk of the message and append it to the signature
      fors_tree_addr
         .set_tree_height(0)
         .set_tree_index(indices.get().at(i) + idx_offset)
         .set_type(Sphincs_Address_Type::ForsKeyGeneration);

      auto sig_location = std::span(signature).subspan(i * params.n() * (params.a() + 1), params.n());
      hashes.PRF(sig_location, public_seed, secret_seed, fors_tree_addr);

      // Compute the authentication path and root for this leaf node
      fors_tree_addr.set_type(Sphincs_Address_Type::ForsTree);
      auto auth_path_location = std::span(signature).subspan(params.n() * (i  * (params.a() + 1) + 1), params.n() * params.a());
      auto roots_location = std::span(roots).subspan(i * params.n(), params.n());

      treehashSpec(roots_location, auth_path_location, params, hashes, secret_seed, public_seed, indices.get().at(i), idx_offset, params.a(), fors_gen_leafx1, fors_tree_addr);
      }

   // Compute the public key by the hash of the concatenation of all roots
   ForsPublicKey pk(params.n());
   hashes.F(std::span(pk), public_seed, fors_pk_addr, std::span(roots));

   return std::make_pair(std::move(pk), std::move(signature));
   }

ForsPublicKey fors_public_key_from_signature(const SphincsHashedMessage& hashed_message,
                                             const ForsSignature& signature,
                                             const SphincsPublicSeed& public_seed,
                                             const Sphincs_Address& address,
                                             const Sphincs_Parameters& params,
                                             Sphincs_Hash_Functions& hashes)
   {
   const auto indices = fors_message_to_indices(hashed_message, params);

   auto fors_tree_addr =
      Sphincs_Address::as_keypair_from(address)
         .set_type(Sphincs_Address::ForsTree);

   auto fors_pk_addr =
      Sphincs_Address::as_keypair_from(address)
         .set_type(Sphincs_Address::ForsTreeRootsCompression);

   std::vector<uint8_t> roots(params.k() * params.n());

   std::vector<uint8_t> leaf(params.n());

   // For each of the k FORS subtrees: Reconstruct the subtree's root node by using the
   // leaf and the authentication path offered in the FORS signature.
   for(size_t i = 0; i < params.k(); ++i)
      {
      uint32_t idx_offset = i * (1 << params.a());

      // Compute the FORS leaf by using the secret leaf contained in the signature
      fors_tree_addr
         .set_tree_height(0)
         .set_tree_index(indices.get().at(i) + idx_offset);
      auto signature_location = std::span(signature).subspan(i * params.n() * (params.a() + 1), params.n());
      hashes.F(leaf, public_seed, fors_tree_addr, signature_location);

      // Reconstruct the subtree's root using the authentication path
      auto auth_path_location = std::span<const uint8_t>(signature).subspan(params.n() * (i  * (params.a() + 1) + 1), params.n() * params.a());
      auto roots_loaction = std::span(roots).subspan(i * params.n(), params.n());
      compute_root_spec(roots_loaction, params, public_seed, hashes, leaf, indices.get().at(i), idx_offset, auth_path_location, params.a(), fors_tree_addr);
      }

   // Reconstruct the public key the signature creates with the hash of the concatenation of all roots
   // Only if the signature is valid, the pk is the correct FORS pk.
   ForsPublicKey pk(params.n());
   hashes.F(pk, public_seed, fors_pk_addr, roots);

   return pk;
   }

}