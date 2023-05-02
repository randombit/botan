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
   BOTAN_ASSERT_NOMSG(message.size() >= params.k() * params.a());

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
                      const Sphincs_Address&,
                      Sphincs_Hash_Functions&)>;

// gen_leaf(current_node, params, sk_seed, pub_seed, idx + idx_offset, tree_address);

void fors_gen_leafx1(std::span<uint8_t> out,
                     const Sphincs_Parameters& params,
                     const SphincsSecretSeed& secret_seed,
                     const SphincsPublicSeed& public_seed,
                     uint32_t address_index,
                     const Sphincs_Address& fors_tree_address,
                     Sphincs_Hash_Functions& hashes)
   {
   // TODO
   }

std::pair<SphincsTreeRoot, SphincsAuthPath>
treehashSpec(const Sphincs_Parameters& params,
             Sphincs_Hash_Functions& hashes,
             const SphincsSecretSeed& sk_seed, const SphincsPublicSeed& pub_seed,
             uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
             GenerateLeafFunction gen_leaf,
             Sphincs_Address& tree_address)
   {
   const uint32_t max_idx = uint32_t((1 << tree_height) - 1);

   std::vector<uint8_t> stack(tree_height * params.n());
   SphincsAuthPath auth_path;
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
            return { SphincsTreeRoot(current_node), auth_path };
            }

         // Check if the node we have is a part of the authentication path; if
         // it is, write it out. The XOR sum of both nodes (at internal_idx and internal_leaf)
         // is 1 iff they have the same parent node in the FORS tree
         if ((internal_idx ^ internal_leaf) == 0x01) {
            auth_path.get().insert(auth_path.end(), current_node.begin(), current_node.end());
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
   }

std::pair<ForsPublicKey, ForsSignature> fors_sign(std::span<const uint8_t> msg,
                                                  const SphincsSecretSeed& secret_seed,
                                                  const SphincsPublicSeed& public_seed,
                                                  const Sphincs_Address& address,
                                                  const Sphincs_Parameters& params,
                                                  Sphincs_Hash_Functions& hash)
   {
   // const auto indices = fors_message_to_indices(msg, params);

   // auto fors_tree_addr =
   //    Sphincs_Address::as_keypair_from(address)
   //       .set_type(Sphincs_Address::ForsTree);

   // auto fors_pk_addr =
   //    Sphincs_Address::as_keypair_from(address)
   //       .set_type(Sphincs_Address::ForsTreeRootsCompression);

   // ForsSignature signature;

   // for(size_t i = 0; i < params.k(); ++i)
   //    {
   //    uint32_t idx_offset = i * (1 << params.a());

   //    fors_tree_addr
   //       .set_tree_height(0)
   //       .set_tree_index(indices.get().at(i) + idx_offset);

   //    //fors_gen_sk TODO: Replace by PRF call
   //    auto sig_append = prf_addr(secret_seed, fors_tree_addr, hash);

   //    signature.get().insert(signature.end(), sig_append.begin(), sig_append.end());

   //    /* Include the secret key part that produces the selected leaf node. */
   //    //fors_gen_sk(sig, sk_seed, fors_tree_addr);
   //    //sig += SPX_N;

   //    /* Compute the authentication path for this leaf node. */
   //    //treehash(roots + i*SPX_N, sig, sk_seed, pub_seed, indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leaf, fors_tree_addr);
   //    //sig += SPX_N * SPX_FORS_HEIGHT;
   //    }



   return {};
   }

ForsPublicKey fors_public_key_from_signature(std::span<const uint8_t> message,
                                             const ForsSignature& signature,
                                             const SphincsPublicSeed& public_seed,
                                             const Sphincs_Address& address,
                                             const Sphincs_Parameters& params,
                                             Sphincs_Hash_Functions& hash)
   {
   return {};
   }

}
