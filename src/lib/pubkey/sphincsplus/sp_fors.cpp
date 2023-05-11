/*
 * FORS - Forest of Random Subsets
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/


#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_types.h>
#include <botan/sp_parameters.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_fors.h>
#include <botan/internal/mgf1.h>
#include <botan/internal/sp_treehash.h>

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

void fors_gen_leaf_spec(std::span<uint8_t> out,
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
   hashes.T(out, public_seed, fors_leaf_address, out);
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

   ForsSignature signature((params.a() + 1) * params.k() * params.n());

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

      auto gen_leaf_bound = std::bind(fors_gen_leaf_spec, std::placeholders::_1, std::ref(params), std::ref(secret_seed), std::ref(public_seed),
                                      std::placeholders::_2, std::ref(fors_tree_addr), std::ref(hashes));

      treehash_spec(roots_location, auth_path_location, params, hashes, public_seed, indices.get().at(i), idx_offset, params.a(),
                   gen_leaf_bound, fors_tree_addr);
      }

   // Compute the public key by the hash of the concatenation of all roots
   ForsPublicKey pk(params.n());
   hashes.T(pk, public_seed, fors_pk_addr, roots);

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
      hashes.T(leaf, public_seed, fors_tree_addr, signature_location);

      // Reconstruct the subtree's root using the authentication path
      auto auth_path_location = std::span<const uint8_t>(signature).subspan(params.n() * (i  * (params.a() + 1) + 1), params.n() * params.a());
      auto roots_loaction = std::span(roots).subspan(i * params.n(), params.n());
      compute_root_spec(roots_loaction, params, public_seed, hashes, leaf, indices.get().at(i), idx_offset, auth_path_location, params.a(), fors_tree_addr);
      }

   // Reconstruct the public key the signature creates with the hash of the concatenation of all roots
   // Only if the signature is valid, the pk is the correct FORS pk.
   ForsPublicKey pk(params.n());
   hashes.T(pk, public_seed, fors_pk_addr, roots);

   return pk;
   }

}
