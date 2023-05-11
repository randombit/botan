/*
* Sphincs+
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/sphincsplus.h>
#include <botan/internal/sp_types.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_fors.h>
#include <botan/internal/sp_xmss.h>

namespace Botan
{

/// @returns sig = message_signature || message
std::vector<uint8_t> sphincsplus_sign(const std::vector<uint8_t>& message,
                                      const secure_vector<uint8_t>& sk_seed_vec,
                                      const secure_vector<uint8_t>& sk_prf_vec,
                                      const std::vector<uint8_t>& pub_seed_vec,
                                      const std::vector<uint8_t>& opt_rand_vec,
                                      const std::vector<uint8_t>& pk_root,
                                      const Sphincs_Parameters& params)
   {
   const SphincsSecretSeed sk_seed(sk_seed_vec);
   const SphincsPublicSeed pub_seed(pub_seed_vec);
   const SphincsSecretPRF sk_prf(sk_prf_vec);
   const SphincsOptionalRandomness opt_rand(opt_rand_vec);

   std::vector<uint8_t> sphincs_sig(params.sphincs_signature_bytes() + message.size());

   SphincsHashedMessage mhash(params.fors_message_bytes());

   auto hashes = Botan::Sphincs_Hash_Functions::create(params);

   /* Compute the digest randomization value (R of spec). */
   auto msg_random_location = std::span(sphincs_sig).subspan(0, params.n());
   hashes->PRF_msg(msg_random_location, sk_prf, opt_rand, message);

   /* Derive the message digest and leaf index from R, PK and M. */
   auto [tree_idx, leaf_idx] = hashes->H_msg(mhash,
                                             msg_random_location,
                                             pub_seed,
                                             pk_root,
                                             message);

   Sphincs_Address wots_addr;
   wots_addr.set_tree(tree_idx).set_keypair(leaf_idx).set_type(Sphincs_Address_Type::WotsHash);

   Sphincs_Address tree_addr;
   tree_addr.set_type(Sphincs_Address_Type::HashTree);

   /* Sign the message hash using FORS. */
   auto fors_sig_location = std::span(sphincs_sig).subspan(msg_random_location.size(), params.fors_signature_bytes());

   auto current_xmss_root = fors_sign(fors_sig_location, mhash, sk_seed, pub_seed, wots_addr, params, *hashes);

   for (size_t i = 0; i < params.d(); i++)
      {
      tree_addr.set_layer(i).set_tree(tree_idx);
      wots_addr.copy_subtree_from(tree_addr).set_keypair(leaf_idx);

      auto xmss_sig_location = std::span(sphincs_sig).subspan(msg_random_location.size() + fors_sig_location.size() +
                                                              i * (params.wots_bytes() + params.tree_height() * params.n()),
                                                              params.wots_bytes() + params.tree_height() * params.n());

      current_xmss_root = xmss_sign(xmss_sig_location, current_xmss_root, pub_seed, sk_seed, wots_addr, tree_addr, leaf_idx, params, *hashes);

      /* Update the indices for the next layer. */
      leaf_idx = (tree_idx & ((1 << params.tree_height()) - 1));
      tree_idx = tree_idx >> params.tree_height();
      }

   // Write the message at the end of the signature
   std::copy(message.begin(), message.end(), sphincs_sig.end() - message.size());

   return sphincs_sig;
   }

/// @returns true iff the signature is valid for the given message
bool sphincsplus_verify(const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& sig,
                        const std::vector<uint8_t>& pub_seed_vec,
                        const std::vector<uint8_t>& pk_root_vec,
                        const Sphincs_Parameters& params,
                        Sphincs_Hash_Functions& hashes)
   {
   const SphincsPublicSeed pub_seed(pub_seed_vec);
   const SphincsXmssRootNode pk_root(pk_root_vec);

   //spx_ctx ctx;
   //const unsigned char *pub_root = pk + SPX_N;
   //unsigned char mhash[SPX_FORS_MSG_BYTES];
   //unsigned char wots_pk[SPX_WOTS_BYTES];
   //WotsPublicKey
   WotsPublicKey wots_pk(params.wots_bytes());
   //SphincsXmssRootNode root(params.n());
   std::vector<uint8_t> leaf(params.n());
   //unsigned int i;
   //uint64_t tree;
   //uint32_t idx_leaf;
   Sphincs_Address wots_addr;
   Sphincs_Address tree_addr;
   Sphincs_Address wots_pk_addr;
   //uint32_t wots_addr[8] = {0};
   //uint32_t tree_addr[8] = {0};
   //uint32_t wots_pk_addr[8] = {0};

   if(sig.size() != params.sphincs_signature_bytes())
      {
      return false;
      }

   // if (siglen != SPX_BYTES) {
   //    return -1;
   // }

   //memcpy(ctx.pub_seed, pk, SPX_N);

   /* This hook allows the hash function instantiation to do whatever
      preparation or computation it needs, based on the public seed. */
   //initialize_hash_function(&ctx);

   wots_addr.set_type(Sphincs_Address_Type::WotsHash);
   tree_addr.set_type(Sphincs_Address_Type::HashTree);
   wots_pk_addr.set_type(Sphincs_Address_Type::WotsPublicKeyCompression);

   //set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
   //set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
   //set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

   /* Derive the message digest and leaf index from R || PK || M. */
   /* The additional SPX_N is a result of the hash domain separator. */
   std::span<const uint8_t> r_location = std::span(sig).subspan(0, params.n());
   SphincsHashedMessage mhash(params.fors_message_bytes());

   // TODO: Adept types for H_msg
   auto [tree_idx, leaf_idx] = hashes.H_msg(mhash, r_location, SphincsPublicSeed(pub_seed_vec), pk_root.get(), message);
   //hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
   //sig += SPX_N;

   /* Layer correctly defaults to 0, so no need to set_layer_addr */
   wots_addr.set_tree(tree_idx).set_keypair(leaf_idx);
   //set_tree_addr(wots_addr, tree_idx);
   //set_keypair_addr(wots_addr, idx_leaf);
   // TODO: Optimize (no copy)
   ForsSignature fors_sig(std::vector(sig.begin() + params.n(), sig.begin() + params.n() + params.fors_signature_bytes()));

   auto root = fors_public_key_from_signature(mhash, fors_sig, pub_seed, wots_addr, params, hashes);
   //fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
   //sig += SPX_FORS_BYTES;

   /* For each subtree.. */
   for (size_t i = 0; i < params.d(); i++) {
      //set_layer_addr(tree_addr, i);
      tree_addr.set_layer(i);
      //set_tree_addr(tree_addr, tree_idx);
      tree_addr.set_tree_index(tree_idx);

      wots_addr.copy_subtree_from(tree_addr);
      wots_addr.set_keypair(leaf_idx);
      //copy_subtree_addr(wots_addr, tree_addr);
      //set_keypair_addr(wots_addr, idx_leaf);

      wots_pk_addr.copy_keypair_from(wots_addr);
      //copy_keypair_addr(wots_pk_addr, wots_addr);

      /* The WOTS public key is only correct if the signature was correct. */
      /* Initially, root is the FORS pk, but on subsequent iterations it is
         the root of the subtree below the currently processed subtree. */
      auto sig_wots_chunk = WotsSignature()
      auto xmss_sig_location = std::span(sig).subspan(msg_random_location.size() + fors_sig_location.size() +
                                                              i * (params.wots_bytes() + params.tree_height() * params.n()),
                                                              params.wots_bytes() + params.tree_height() * params.n());
      wots_pk = wots_public_key_from_signature(root, WotsSignature(sig), pub_seed, wots_addr, params, hashes);
      //wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
      //wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
      sig += SPX_WOTS_BYTES;

      /* Compute the leaf node using the WOTS public key. */
      thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);
      hashes.T(leaf, pub_seed, )

      /* Compute the root node of this subtree. */
      compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                  &ctx, tree_addr);
      sig += SPX_TREE_HEIGHT * SPX_N;

      /* Update the indices for the next layer. */
      idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
      tree = tree >> SPX_TREE_HEIGHT;
   }

   /* Check if the root node equals the root node in the public key. */
   if (memcmp(root, pub_root, SPX_N)) {
      return -1;
   }

   return 0;



   return false;
   }

}