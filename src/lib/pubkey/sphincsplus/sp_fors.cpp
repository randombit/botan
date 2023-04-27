/*
 * FORS - Forest of Random Subsets
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/sp_address.h>
#include <botan/internal/sp_fors.h>
#include <botan/internal/thread_pool.h>
#include <botan/internal/mgf1.h>

#include <botan/hash.h>

#include <iostream>

namespace Botan
{

// out: root, auth_path
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> treehash(const SphincsSecretSeed& secret_seed,
                                                               const SphincsPublicSeed& public_seed,
                                                               const uint32_t leaf_index,
                                                               const uint32_t idx_offset,
                                                               const FORS_Parameters& params,
                                                               const Sphincs_Address& fors_tree_address,
                                                               HashFunction& hash)
   {
   std::vector<uint8_t> stack;
   std::vector<uint32_t> heights;
   uint32_t offset = 0;

   uint32_t idx;
   uint32_t tree_idx;



   return std::pair<std::vector<uint8_t>, std::vector<uint8_t>>();
   }

// TODO: Test
std::vector<uint8_t> thash(const std::vector<uint8_t>& in,
                           uint32_t inblocks,
                           const SphincsPublicSeed& pub_seed,
                           const Sphincs_Address& address,
                           const FORS_Parameters& params,
                           HashFunction& hash)
   {
   std::vector<uint8_t> buf;
   std::vector<uint8_t> bitmask;

   auto address_bytes = address.to_bytes();
   // TODO: Use concat
   buf.insert(buf.end(), pub_seed.begin(), pub_seed.end());
   buf.insert(buf.end(), address_bytes.begin(), address_bytes.end());


   bitmask.resize(inblocks * params.n());
   mgf1_mask(hash, buf.data(), buf.size(), bitmask.data(), bitmask.size());

   // TODO optimize push_back
   for (size_t i = 0; i < inblocks * params.n(); i++) {
      buf.push_back(in.at(i) ^ bitmask.at(i));
   }

   hash.update(buf);
   std::vector<uint8_t> outbuf = hash.final_stdvec();

   return outbuf;
   }

std::vector<uint8_t> prf_addr(const SphincsSecretSeed& secret_seed,
                              const Sphincs_Address& address,
                              HashFunction& hash)
   {
   hash.update(secret_seed);
   address.apply_to_hash(hash);
   return hash.final_stdvec();
   }

std::pair<ForsPublicKey, ForsSignature> fors_sign(std::span<const uint8_t> msg,
                                                  const SphincsSecretSeed& secret_seed,
                                                  const SphincsPublicSeed& public_seed,
                                                  const Sphincs_Address& address,
                                                  const FORS_Parameters& params,
                                                  HashFunction& hash)
   {
   const auto indices = fors_message_to_indices(msg, params);

   auto fors_tree_addr =
      Sphincs_Address::as_keypair_from(address)
         .set_type(Sphincs_Address::ForsTree);

   auto fors_pk_addr =
      Sphincs_Address::as_keypair_from(address)
         .set_type(Sphincs_Address::ForsTreeRootsCompression);

   ForsSignature signature;

   for (size_t i = 0; i < params.k(); i++)
      {
      uint32_t idx_offset = i * (1 << params.a());

      fors_tree_addr
         .set_tree_height(0)
         .set_tree_index(indices.get().at(i) + idx_offset);

      //fors_gen_sk TODO: Replace by PRF call
      auto sig_append = prf_addr(secret_seed, fors_tree_addr, hash);

      signature.get().insert(signature.end(), sig_append.begin(), sig_append.end());

      /* Include the secret key part that produces the selected leaf node. */
      //fors_gen_sk(sig, sk_seed, fors_tree_addr);
      //sig += SPX_N;

      /* Compute the authentication path for this leaf node. */
      //treehash(roots + i*SPX_N, sig, sk_seed, pub_seed, indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leaf, fors_tree_addr);
      //sig += SPX_N * SPX_FORS_HEIGHT;
      }



   return {};
   }

ForsPublicKey fors_public_key_from_signature(std::span<const uint8_t> message,
                                             const ForsSignature& signature,
                                             const SphincsPublicSeed& public_seed,
                                             const Sphincs_Address& address,
                                             const FORS_Parameters& params,
                                             HashFunction& hash)
   {
   return {};
   }

ForsIndices fors_message_to_indices(std::span<const uint8_t> message, const FORS_Parameters& params)
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



}
