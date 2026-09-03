/*
 * XMSS Tree Builder
 * (C) 2016,2017,2018 Matthias Gierlings
 * (C) 2019,2026 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_tree_builder.h>

#include <botan/mem_ops.h>
#include <botan/internal/xmss_common_ops.h>
#include <botan/internal/xmss_hash.h>
#include <algorithm>

namespace Botan {

namespace {

/**
* Number of leaves whose WOTS+ keys and L-trees are computed at once,
* so that the hash calls of each step are batched across all of them
*/
constexpr size_t LEAF_BATCH = 128;

}  // namespace

secure_vector<uint8_t> XMSS_Tree_Builder::tree_hash(size_t start_idx,
                                                    size_t target_node_height,
                                                    const XMSS_Address& adrs_in,
                                                    XMSS_Hash& hash) const {
   BOTAN_ASSERT_NOMSG(target_node_height <= 30);
   BOTAN_ASSERT((start_idx % (static_cast<size_t>(1) << target_node_height)) == 0,
                "Start index must be divisible by 2^{target node height}.");

   const size_t n = m_wots_params.element_size();
   const secure_vector<uint8_t>& seed = this->public_seed();
   const size_t last_idx = (static_cast<size_t>(1) << target_node_height) + start_idx;

   const size_t batch = std::min<size_t>(LEAF_BATCH, last_idx - start_idx);
   secure_vector<uint8_t> leaves(batch * n);

   // node stack, holds all nodes on stack and one extra "pending" node. This
   // temporary node referred to as "node" in the XMSS standard document stays
   // a pending element, meaning it is not regarded as element on the stack
   // until level is increased.
   std::vector<secure_vector<uint8_t>> nodes(target_node_height + 1, secure_vector<uint8_t>(n));
   std::vector<uint8_t> node_levels(target_node_height + 1);

   uint8_t level = 0;  // current level on the node stack.

   XMSS_Address adrs(adrs_in);
   adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);

   for(size_t i = start_idx; i < last_idx; i++) {
      const size_t b = (i - start_idx) % batch;
      if(b == 0) {
         const size_t count = std::min(batch, last_idx - i);
         compute_leaves(std::span(leaves).first(count * n), i, count, adrs, hash);
      }

      copy_mem(nodes[level], std::span(leaves).subspan(b * n, n));
      node_levels[level] = 0;

      adrs.set_tree_height(0);
      adrs.set_tree_index(static_cast<uint32_t>(i));

      while(level > 0 && node_levels[level] == node_levels[level - 1]) {
         adrs.set_tree_index(((adrs.get_tree_index() - 1) >> 1));
         XMSS_Common_Ops::randomize_tree_hash(nodes[level - 1], nodes[level - 1], nodes[level], adrs, seed, hash, n);
         node_levels[level - 1]++;
         level--;  //Pop stack top element
         adrs.set_tree_height(adrs.get_tree_height() + 1);
      }
      level++;  //push temporary node to stack
   }
   return nodes[level - 1];
}

void XMSS_Tree_Builder::compute_leaves(
   std::span<uint8_t> leaves, size_t start_idx, size_t count, const XMSS_Address& adrs, XMSS_Hash& hash) const {
   const size_t n = m_wots_params.element_size();
   const size_t len = m_wots_params.len();

   BOTAN_ASSERT_NOMSG(leaves.size() == count * n);

   XMSS_Address ots_adrs(adrs);
   ots_adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);

   std::vector<XMSS_Address> ots_addrs(count * len, ots_adrs);
   for(size_t k = 0; k < count; ++k) {
      for(size_t i = 0; i < len; ++i) {
         ots_addrs[k * len + i].set_ots_address(static_cast<uint32_t>(start_idx + k));
         ots_addrs[k * len + i].set_chain_address(static_cast<uint32_t>(i));
      }
   }

   secure_vector<uint8_t> keys(count * len * n);
   wots_private_keys(keys, ots_addrs, hash);

   // Algorithm 4: "WOTS_genPK", transforming the private keys in place
   const std::vector<uint8_t> from(count * len, 0);
   const std::vector<uint8_t> to(count * len, static_cast<uint8_t>(m_wots_params.wots_parameter() - 1));
   xmss_wots_chains(m_wots_params, keys, from, to, ots_addrs, public_seed(), hash);

   XMSS_Address ltree_adrs(adrs);
   ltree_adrs.set_type(XMSS_Address::Type::LTree_Address);

   std::vector<XMSS_Address> ltree_addrs(count, ltree_adrs);
   for(size_t k = 0; k < count; ++k) {
      ltree_addrs[k].set_ltree_address(static_cast<uint32_t>(start_idx + k));
   }
   XMSS_Common_Ops::create_l_trees(leaves, keys, ltree_addrs, public_seed(), hash, n, len);
}

void XMSS_Tree_Builder::wots_private_keys(std::span<uint8_t> sks,
                                          std::span<const XMSS_Address> addrs,
                                          XMSS_Hash& hash) const {
   const size_t n = m_wots_params.element_size();
   const size_t len = m_wots_params.len();
   const size_t count = addrs.size();

   BOTAN_ASSERT_NOMSG(sks.size() == count * n && count % len == 0);

   switch(m_wots_derivation_method) {
      case WOTS_Derivation_Method::NIST_SP800_208: {
         const size_t data_len = public_seed().size() + addrs[0].size();
         std::vector<uint8_t> data_arena(count * data_len);

         std::vector<std::span<uint8_t>> outputs(count);
         std::vector<std::span<const uint8_t>> data(count);

         for(size_t i = 0; i < count; ++i) {
            const auto slot = std::span(data_arena).subspan(i * data_len, data_len);
            copy_mem(slot.first(public_seed().size()), public_seed());
            copy_mem(slot.subspan(public_seed().size()), addrs[i].bytes());

            outputs[i] = sks.subspan(i * n, n);
            data[i] = slot;
         }

         hash.prf_keygen_batch(outputs, m_private_seed, data);
         return;
      }
      case WOTS_Derivation_Method::Botan2x: {
         for(size_t k = 0; k < count / len; ++k) {
            const XMSS_WOTS_PrivateKey sk(m_wots_params, m_private_seed, addrs[k * len], hash);
            for(size_t i = 0; i < len; ++i) {
               copy_mem(sks.subspan((k * len + i) * n, n), sk.key_data()[i]);
            }
         }
         return;
      }
   }

   throw Invalid_State("WOTS derivation method is out of the enum's range");
}

XMSS_WOTS_PrivateKey XMSS_Tree_Builder::wots_private_key_for(const XMSS_Address& adrs, XMSS_Hash& hash) const {
   switch(m_wots_derivation_method) {
      case WOTS_Derivation_Method::NIST_SP800_208:
         return XMSS_WOTS_PrivateKey(m_wots_params, public_seed(), m_private_seed, adrs, hash);
      case WOTS_Derivation_Method::Botan2x:
         return XMSS_WOTS_PrivateKey(m_wots_params, m_private_seed, adrs, hash);
   }

   throw Invalid_State("WOTS derivation method is out of the enum's range");
}

}  // namespace Botan
