/*
 * FORS - Forest of Random Subsets
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/sp_fors.h>

#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/sp_parameters.h>

#include <botan/internal/sp_address.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_treehash.h>
#include <botan/internal/sp_types.h>
#include <botan/internal/stl_util.h>

#include <functional>
#include <utility>

namespace Botan {

namespace {

std::vector<TreeNodeIndex> fors_message_to_indices(std::span<const uint8_t> message, const Sphincs_Parameters& params) {
   BOTAN_ASSERT_NOMSG((message.size() * 8) >= (params.k() * params.a()));

   std::vector<TreeNodeIndex> indices(params.k());

   uint32_t offset = 0;

   for(auto& idx : indices) {
      for(uint32_t i = 0; i < params.a(); ++i, ++offset) {
         idx ^= (((message[offset >> 3] >> (offset & 0x7)) & 0x1) << i);
      }
   }

   return indices;
}

}  // namespace

SphincsTreeNode fors_sign_and_pkgen(StrongSpan<ForsSignature> sig_out,
                                    const SphincsHashedMessage& hashed_message,
                                    const SphincsSecretSeed& secret_seed,
                                    const Sphincs_Address& address,
                                    const Sphincs_Parameters& params,
                                    Sphincs_Hash_Functions& hashes) {
   BOTAN_ASSERT_NOMSG(sig_out.size() == params.fors_signature_bytes());

   const auto indices = fors_message_to_indices(hashed_message, params);

   auto fors_tree_addr = Sphincs_Address::as_keypair_from(address);

   auto fors_pk_addr = Sphincs_Address::as_keypair_from(address).set_type(Sphincs_Address::ForsTreeRootsCompression);

   std::vector<uint8_t> roots_buffer(params.k() * params.n());
   BufferStuffer roots(roots_buffer);
   BufferStuffer sig(sig_out);

   // Buffer to hold the FORS leafs during tree traversal
   // (Avoids a secure_vector allocation/deallocation in the hot path)
   ForsLeafSecret fors_leaf_secret(params.n());

   // For each of the k FORS subtrees: Compute the secret leaf, the authentication path
   // and the trees' root and append the signature respectively
   BOTAN_ASSERT_NOMSG(indices.size() == params.k());
   for(uint32_t i = 0; i < params.k(); ++i) {
      uint32_t idx_offset = i * (1 << params.a());

      // Compute the secret leaf given by the chunk of the message and append it to the signature
      fors_tree_addr.set_tree_height(TreeLayerIndex(0))
         .set_tree_index(indices[i] + idx_offset)
         .set_type(Sphincs_Address_Type::ForsKeyGeneration);

      hashes.PRF(sig.next<ForsLeafSecret>(params.n()), secret_seed, fors_tree_addr);

      // Compute the authentication path and root for this leaf node
      fors_tree_addr.set_type(Sphincs_Address_Type::ForsTree);

      GenerateLeafFunction fors_gen_leaf = [&](StrongSpan<SphincsTreeNode> out_root, TreeNodeIndex address_index) {
         fors_tree_addr.set_tree_index(address_index);
         fors_tree_addr.set_type(Sphincs_Address_Type::ForsKeyGeneration);

         hashes.PRF(fors_leaf_secret, secret_seed, fors_tree_addr);

         fors_tree_addr.set_type(Sphincs_Address_Type::ForsTree);
         hashes.T(out_root, fors_tree_addr, fors_leaf_secret);
      };

      treehash(roots.next<SphincsTreeNode>(params.n()),
               sig.next<SphincsAuthenticationPath>(params.a() * params.n()),
               params,
               hashes,
               indices[i],
               idx_offset,
               params.a(),
               fors_gen_leaf,
               fors_tree_addr);
   }

   BOTAN_ASSERT_NOMSG(sig.full());
   BOTAN_ASSERT_NOMSG(roots.full());

   // Compute the public key by the hash of the concatenation of all roots
   return hashes.T<SphincsTreeNode>(fors_pk_addr, roots_buffer);
}

SphincsTreeNode fors_public_key_from_signature(const SphincsHashedMessage& hashed_message,
                                               StrongSpan<const ForsSignature> signature,
                                               const Sphincs_Address& address,
                                               const Sphincs_Parameters& params,
                                               Sphincs_Hash_Functions& hashes) {
   const auto indices = fors_message_to_indices(hashed_message, params);

   auto fors_tree_addr = Sphincs_Address::as_keypair_from(address).set_type(Sphincs_Address::ForsTree);

   auto fors_pk_addr = Sphincs_Address::as_keypair_from(address).set_type(Sphincs_Address::ForsTreeRootsCompression);

   BufferSlicer s(signature);
   std::vector<uint8_t> roots_buffer(params.k() * params.n());
   BufferStuffer roots(roots_buffer);

   // For each of the k FORS subtrees: Reconstruct the subtree's root node by using the
   // leaf and the authentication path offered in the FORS signature.
   BOTAN_ASSERT_NOMSG(indices.size() == params.k());
   for(uint32_t i = 0; i < params.k(); ++i) {
      uint32_t idx_offset = i * (1 << params.a());

      // Compute the FORS leaf by using the secret leaf contained in the signature
      fors_tree_addr.set_tree_height(TreeLayerIndex(0)).set_tree_index(indices[i] + idx_offset);
      auto fors_leaf_secret = s.take<ForsLeafSecret>(params.n());
      auto auth_path = s.take<SphincsAuthenticationPath>(params.n() * params.a());
      auto leaf = hashes.T<SphincsTreeNode>(fors_tree_addr, fors_leaf_secret);

      // Reconstruct the subtree's root using the authentication path
      compute_root(roots.next<SphincsTreeNode>(params.n()),
                   params,
                   hashes,
                   leaf,
                   indices[i],
                   idx_offset,
                   auth_path,
                   params.a(),
                   fors_tree_addr);
   }

   BOTAN_ASSERT_NOMSG(roots.full());

   // Reconstruct the public key the signature creates with the hash of the concatenation of all roots
   // Only if the signature is valid, the pk is the correct FORS pk.
   return hashes.T<SphincsTreeNode>(fors_pk_addr, roots_buffer);
}

}  // namespace Botan
