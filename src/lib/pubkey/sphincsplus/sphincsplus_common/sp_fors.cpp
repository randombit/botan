/*
 * FORS - Forest of Random Subsets (FIPS 205, Section 8)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/sp_fors.h>

#include <botan/assert.h>
#include <botan/sp_parameters.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_treehash.h>
#include <botan/internal/sp_types.h>

namespace Botan {

namespace {

/// FIPS 205, Algorithm 4: base_2^b(X,b,out_len) with b = a and out_len = k (for usage in FORS)
std::vector<TreeNodeIndex> fors_message_to_indices(std::span<const uint8_t> message, const Sphincs_Parameters& params) {
   BOTAN_ASSERT_NOMSG((message.size() * 8) >= (params.k() * params.a()));

   std::vector<TreeNodeIndex> indices(params.k());

   uint32_t offset = 0;

   // This is one of the few places where the logic of SPHINCS+ round 3.1 and SLH-DSA differs
   auto update_idx = [&]() -> std::function<void(TreeNodeIndex&, uint32_t)> {
#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
      if(params.is_slh_dsa()) {
         return [&](TreeNodeIndex& idx, uint32_t i) {
            idx ^= (((message[offset >> 3] >> (~offset & 0x7)) & 0x1) << (params.a() - 1 - i));
         };
      }
#endif
#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
      if(!params.is_slh_dsa()) {
         return [&](TreeNodeIndex& idx, uint32_t i) { idx ^= (((message[offset >> 3] >> (offset & 0x7)) & 0x1) << i); };
      }
#endif
      throw Internal_Error("Missing FORS index update logic for SPHINCS+ or SLH-DSA");
   }();

   for(auto& idx : indices) {
      for(uint32_t i = 0; i < params.a(); ++i, ++offset) {
         update_idx(idx, i);
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

   // Scratch space for batched leaf generation, reused across subtrees
   std::vector<Sphincs_Address> leaf_addrs;
   secure_vector<uint8_t> leaf_secrets;
   std::vector<std::span<uint8_t>> secret_spans;
   std::vector<std::span<const uint8_t>> csecret_spans;
   std::vector<std::span<uint8_t>> leaf_spans;

   // Each leaf is the hash of a secret derived from the leaf's address
   const GenerateLeavesFunction fors_gen_leaves = [&](std::span<uint8_t> out, TreeNodeIndex first_idx, uint32_t count) {
      leaf_addrs.assign(count, fors_tree_addr);
      leaf_secrets.resize(count * params.n());
      secret_spans.resize(count);
      csecret_spans.resize(count);
      leaf_spans.resize(count);

      for(uint32_t j = 0; j != count; ++j) {
         leaf_addrs[j]
            .set_type(Sphincs_Address_Type::ForsKeyGeneration)
            .set_tree_height(TreeLayerIndex(0))
            .set_tree_index(first_idx + j);
         secret_spans[j] = std::span(leaf_secrets).subspan(j * params.n(), params.n());
         csecret_spans[j] = secret_spans[j];
         leaf_spans[j] = out.subspan(j * params.n(), params.n());
      }

      hashes.PRF_batch(secret_spans, secret_seed, leaf_addrs);

      for(uint32_t j = 0; j != count; ++j) {
         leaf_addrs[j].set_type(Sphincs_Address_Type::ForsTree);
      }

      hashes.T_batch(leaf_spans, leaf_addrs, csecret_spans);
   };

   // For each of the k FORS subtrees: Compute the secret leaf, the authentication path
   // and the trees' root and append the signature respectively
   BOTAN_ASSERT_NOMSG(indices.size() == params.k());
   for(uint32_t i = 0; i < params.k(); ++i) {
      const uint32_t idx_offset = i * (1 << params.a());

      // Compute the secret leaf given by the chunk of the message and append it to the signature
      fors_tree_addr.set_type(Sphincs_Address_Type::ForsKeyGeneration)
         .set_tree_height(TreeLayerIndex(0))
         .set_tree_index(indices[i] + idx_offset);

      hashes.PRF(sig.next<ForsLeafSecret>(params.n()), secret_seed, fors_tree_addr);

      // Compute the authentication path and root for this leaf node
      fors_tree_addr.set_type(Sphincs_Address_Type::ForsTree);

      treehash(roots.next<SphincsTreeNode>(params.n()),
               sig.next<SphincsAuthenticationPath>(params.a() * params.n()),
               params,
               hashes,
               indices[i],
               idx_offset,
               params.a(),
               fors_gen_leaves,
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
      const uint32_t idx_offset = i * (1 << params.a());

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
