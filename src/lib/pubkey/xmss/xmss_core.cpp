/*
 * XMSS Core
 * Some core algorithms of XMSS that are shared across operations and with XMSS^MT
 * (C) 2016,2017 Matthias Gierlings
 * (C) 2019 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_core.h>

#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_wots.h>
#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif
#include <array>
#include <future>

namespace Botan {

void XMSS_Core_Ops::randomize_tree_hash(secure_vector<uint8_t>& result,
                                        const secure_vector<uint8_t>& left,
                                        const secure_vector<uint8_t>& right,
                                        XMSS_Address adrs,
                                        const secure_vector<uint8_t>& seed,
                                        XMSS_Hash& hash,
                                        size_t xmss_element_size) {
   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);
   secure_vector<uint8_t> key;
   hash.prf(key, seed, adrs.bytes());

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_MSB_Mode);
   secure_vector<uint8_t> bitmask_l;
   hash.prf(bitmask_l, seed, adrs.bytes());

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_LSB_Mode);
   secure_vector<uint8_t> bitmask_r;
   hash.prf(bitmask_r, seed, adrs.bytes());

   BOTAN_ASSERT(bitmask_l.size() == left.size() && bitmask_r.size() == right.size(),
                "Bitmask size doesn't match node size.");

   secure_vector<uint8_t> concat_xor(xmss_element_size * 2);
   for(size_t i = 0; i < left.size(); i++) {
      concat_xor[i] = left[i] ^ bitmask_l[i];
      concat_xor[i + left.size()] = right[i] ^ bitmask_r[i];
   }

   hash.h(result, key, concat_xor);
}

void XMSS_Core_Ops::create_l_tree(secure_vector<uint8_t>& result,
                                  wots_keysig_t pk,
                                  XMSS_Address adrs,
                                  const secure_vector<uint8_t>& seed,
                                  XMSS_Hash& hash,
                                  size_t xmss_element_size,
                                  size_t xmss_wots_len) {
   size_t l = xmss_wots_len;
   adrs.set_tree_height(0);

   while(l > 1) {
      for(size_t i = 0; i < l >> 1; i++) {
         adrs.set_tree_index(static_cast<uint32_t>(i));
         randomize_tree_hash(pk[i], pk[2 * i], pk[2 * i + 1], adrs, seed, hash, xmss_element_size);
      }
      if((l & 0x01) == 0x01) {
         pk[l >> 1] = pk[l - 1];
      }
      l = (l >> 1) + (l & 0x01);
      adrs.set_tree_height(adrs.get_tree_height() + 1);
   }
   result = pk[0];
}

secure_vector<uint8_t> XMSS_Core_Ops::root_from_signature(uint32_t idx_leaf,
                                                          const XMSS_TreeSignature& tree_sig,
                                                          const secure_vector<uint8_t>& msg,
                                                          XMSS_Address adrs,
                                                          const secure_vector<uint8_t>& seed,
                                                          XMSS_Hash& hash,
                                                          size_t xmss_element_size,
                                                          size_t xmss_tree_height,
                                                          size_t xmss_wots_len,
                                                          XMSS_WOTS_Parameters::ots_algorithm_t ots_oid) {
   BOTAN_ASSERT_NOMSG(xmss_tree_height > 0 && xmss_tree_height < 32);
   adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   adrs.set_ots_address(idx_leaf);

   const XMSS_WOTS_Parameters wots_params(ots_oid);
   const XMSS_WOTS_PublicKey pub_key_ots(wots_params, seed, tree_sig.ots_signature, msg, adrs, hash);

   adrs.set_type(XMSS_Address::Type::LTree_Address);
   adrs.set_ltree_address(idx_leaf);

   std::array<secure_vector<uint8_t>, 2> node;
   XMSS_Core_Ops::create_l_tree(node[0], pub_key_ots.key_data(), adrs, seed, hash, xmss_element_size, xmss_wots_len);

   adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
   adrs.set_tree_index(idx_leaf);

   for(size_t k = 0; k < xmss_tree_height; k++) {
      adrs.set_tree_height(static_cast<uint32_t>(k));
      if(((idx_leaf / (static_cast<size_t>(1) << k)) & 0x01) == 0) {
         adrs.set_tree_index(adrs.get_tree_index() >> 1);
         XMSS_Core_Ops::randomize_tree_hash(
            node[1], node[0], tree_sig.authentication_path[k], adrs, seed, hash, xmss_element_size);
      } else {
         adrs.set_tree_index((adrs.get_tree_index() - 1) >> 1);
         XMSS_Core_Ops::randomize_tree_hash(
            node[1], tree_sig.authentication_path[k], node[0], adrs, seed, hash, xmss_element_size);
      }
      node[0] = node[1];
   }

   return node[0];
}

secure_vector<uint8_t> XMSS_Core_Ops::tree_hash(
   uint32_t start_idx,
   size_t target_node_height,
   XMSS_Address adrs,
   XMSS_Hash& hash,
   const XMSS_WOTS_Parameters& wots_params,
   const secure_vector<uint8_t>& public_seed,
   const std::function<XMSS_WOTS_PublicKey(XMSS_Address adrs, XMSS_Hash& hash)>& wots_public_key_for_fn) {
   BOTAN_ASSERT_NOMSG(target_node_height <= 30);
   BOTAN_ASSERT((start_idx % (static_cast<size_t>(1) << target_node_height)) == 0,
                "Start index must be divisible by 2^{target node height}.");

#if defined(BOTAN_HAS_THREAD_UTILS)
   // determine number of parallel tasks to split the tree_hashing into.

   Thread_Pool& thread_pool = Thread_Pool::global_instance();

   const size_t split_level = std::min(target_node_height, thread_pool.worker_count());

   // skip parallelization overhead for leaf nodes.
   if(split_level == 0) {
      secure_vector<uint8_t> result;
      tree_hash_subtree(
         result, start_idx, target_node_height, adrs, hash, wots_params, public_seed, wots_public_key_for_fn);
      return result;
   }

   const size_t subtrees = static_cast<size_t>(1) << split_level;
   const uint32_t last_idx = (static_cast<uint32_t>(1) << (target_node_height)) + start_idx;
   const uint32_t offs = (last_idx - start_idx) / static_cast<uint32_t>(subtrees);
   // this cast cannot overflow because target_node_height is limited
   uint8_t level = static_cast<uint8_t>(split_level);  // current level in the tree

   BOTAN_ASSERT((last_idx - start_idx) % subtrees == 0,
                "Number of worker threads in tree_hash need to divide range "
                "of calculated nodes.");

   std::vector<secure_vector<uint8_t>> nodes(subtrees, secure_vector<uint8_t>(wots_params.element_size()));
   std::vector<XMSS_Address> node_addresses(subtrees, adrs);
   std::vector<XMSS_Hash> xmss_hash(subtrees, hash);
   std::vector<std::future<XMSS_Address>> work_treehash;
   std::vector<std::future<void>> work_randthash;

   // Calculate multiple subtrees in parallel.
   for(size_t i = 0; i < subtrees; i++) {
      node_addresses[i].set_type(XMSS_Address::Type::Hash_Tree_Address);

      using tree_hash_subtree_fn_t =
         XMSS_Address (*)(secure_vector<uint8_t>&,
                          uint32_t,
                          size_t,
                          XMSS_Address,
                          XMSS_Hash&,
                          const XMSS_WOTS_Parameters&,
                          const secure_vector<uint8_t>&,
                          const std::function<XMSS_WOTS_PublicKey(XMSS_Address, XMSS_Hash&)>&);

      const tree_hash_subtree_fn_t work_fn = &XMSS_Core_Ops::tree_hash_subtree;

      work_treehash.push_back(thread_pool.run(work_fn,
                                              std::ref(nodes[i]),
                                              start_idx + static_cast<uint32_t>(i) * offs,
                                              target_node_height - split_level,
                                              node_addresses[i],
                                              std::ref(xmss_hash[i]),
                                              std::cref(wots_params),
                                              std::cref(public_seed),
                                              std::cref(wots_public_key_for_fn)));
   }

   for(size_t i = 0; i < work_treehash.size(); i++) {
      // retrieve the addresses for the computed nodes
      node_addresses[i] = work_treehash[i].get();
   }
   work_treehash.clear();

   // Parallelize the top tree levels horizontally
   while(level-- > 1) {
      std::vector<secure_vector<uint8_t>> ro_nodes(nodes.begin(),
                                                   nodes.begin() + (static_cast<size_t>(1) << (level + 1)));

      for(size_t i = 0; i < (static_cast<size_t>(1) << level); i++) {
         BOTAN_ASSERT_NOMSG(xmss_hash.size() > i);

         node_addresses[i].set_tree_height(static_cast<uint32_t>(target_node_height - (level + 1)));
         node_addresses[i].set_tree_index((node_addresses[2 * i + 1].get_tree_index() - 1) >> 1);

         work_randthash.push_back(thread_pool.run(&XMSS_Core_Ops::randomize_tree_hash,
                                                  std::ref(nodes[i]),
                                                  std::cref(ro_nodes[2 * i]),
                                                  std::cref(ro_nodes[2 * i + 1]),
                                                  std::ref(node_addresses[i]),
                                                  std::cref(public_seed),
                                                  std::ref(xmss_hash[i]),
                                                  wots_params.element_size()));
      }

      for(auto& w : work_randthash) {
         w.get();
      }
      work_randthash.clear();
   }

   // Avoid creation an extra thread to calculate root node.
   node_addresses[0].set_tree_height(static_cast<uint32_t>(target_node_height - 1));
   node_addresses[0].set_tree_index((node_addresses[1].get_tree_index() - 1) >> 1);
   XMSS_Core_Ops::randomize_tree_hash(
      nodes[0], nodes[0], nodes[1], node_addresses[0], public_seed, hash, wots_params.element_size());
   return nodes[0];
#else
   secure_vector<uint8_t> result;
   tree_hash_subtree(
      result, start_idx, target_node_height, adrs, hash, wots_params, public_seed, wots_public_key_for_fn);
   return result;
#endif
}

XMSS_Address XMSS_Core_Ops::tree_hash_subtree(
   secure_vector<uint8_t>& result,
   uint32_t start_idx,
   size_t target_node_height,
   XMSS_Address adrs,
   XMSS_Hash& hash,
   const XMSS_WOTS_Parameters& wots_params,
   const secure_vector<uint8_t>& public_seed,
   const std::function<XMSS_WOTS_PublicKey(XMSS_Address adrs, XMSS_Hash& hash)>& wots_public_key_for_fn) {
   std::vector<secure_vector<uint8_t>> nodes(target_node_height + 1,
                                             secure_vector<uint8_t>(wots_params.element_size()));

   // node stack, holds all nodes on stack and one extra "pending" node. This
   // temporary node referred to as "node" in the XMSS standard document stays
   // a pending element, meaning it is not regarded as element on the stack
   // until level is increased.
   std::vector<uint8_t> node_levels(target_node_height + 1);

   uint8_t level = 0;  // current level on the node stack.
   const uint32_t last_idx = (static_cast<uint32_t>(1) << target_node_height) + start_idx;

   for(uint32_t i = start_idx; i < last_idx; i++) {
      adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
      adrs.set_ots_address(static_cast<uint32_t>(i));
      const XMSS_WOTS_PublicKey pk = wots_public_key_for_fn(adrs, hash);

      adrs.set_type(XMSS_Address::Type::LTree_Address);
      adrs.set_ltree_address(static_cast<uint32_t>(i));
      XMSS_Core_Ops::create_l_tree(
         nodes[level], pk.key_data(), adrs, public_seed, hash, wots_params.element_size(), wots_params.len());
      node_levels[level] = 0;

      adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
      adrs.set_tree_index(static_cast<uint32_t>(i));

      while(level > 0 && node_levels[level] == node_levels[level - 1]) {
         adrs.set_tree_index(((adrs.get_tree_index() - 1) >> 1));
         XMSS_Core_Ops::randomize_tree_hash(
            nodes[level - 1], nodes[level - 1], nodes[level], adrs, public_seed, hash, wots_params.element_size());
         node_levels[level - 1]++;
         level--;  //Pop stack top element
         adrs.set_tree_height(adrs.get_tree_height() + 1);
      }
      level++;  //push temporary node to stack
   }
   result = nodes[level - 1];

   return adrs;
}

}  // namespace Botan
