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

   Sphincs_Address wots_addr;
   Sphincs_Address tree_addr;

   auto hashes = Botan::Sphincs_Hash_Functions::create(params);

   wots_addr.set_type(Sphincs_Address_Type::WotsHash);
   tree_addr.set_type(Sphincs_Address_Type::HashTree);

   /* Compute the digest randomization value. */
   auto msg_random_location = std::span(sphincs_sig).subspan(0, params.n());

   hashes->PRF_msg(msg_random_location, sk_prf, opt_rand, message);

   /* Derive the message digest and leaf index from R, PK and M. */
   auto [tree_idx, leaf_idx] = hashes->H_msg(mhash,
                                             msg_random_location,
                                             pub_seed,
                                             pk_root,
                                             message);

   wots_addr.set_tree(tree_idx).set_keypair(leaf_idx);

   /* Sign the message hash using FORS. */
   auto fors_sig_location = std::span(sphincs_sig).subspan(msg_random_location.size(), params.fors_signature_bytes());

   // TODO: Without copy
   auto [current_xmss_root, fors_sig] = fors_sign(mhash, sk_seed, pub_seed, wots_addr, params, *hashes);

   std::copy(fors_sig.begin(), fors_sig.end(), fors_sig_location.begin());

   for (size_t i = 0; i < params.d(); i++)
      {
      tree_addr.set_layer(i).set_tree(tree_idx);

      wots_addr.copy_subtree_from(tree_addr);
      wots_addr.set_keypair(leaf_idx);
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


}