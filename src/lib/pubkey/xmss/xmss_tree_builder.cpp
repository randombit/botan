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

namespace Botan {

namespace {

/**
* Number of leaves whose WOTS+ keys and L-trees are computed at once,
* so that the hash calls of each step are batched across all of them
*/
constexpr uint32_t LEAF_BATCH = 128;

}  // namespace

Merkle_Tree_Builder XMSS_Tree_Builder::merkle_tree(size_t height, const XMSS_Address& adrs, XMSS_Hash& hash) const {
   BOTAN_ASSERT_NOMSG(height <= 30);

   const size_t n = m_wots_params.element_size();

   auto leaf_fn = [builder = *this, adrs, &hash](std::span<uint8_t> out, uint32_t first_leaf, uint32_t count) {
      builder.compute_leaves(out, first_leaf, count, adrs, hash);
   };

   // Algorithm 9: "treeHash", which addresses a node by the height of its
   // children and its own index
   auto node_fn =
      [builder = *this, adrs, &hash, n](
         std::span<uint8_t> out, uint32_t j, uint32_t first_t, uint32_t count, std::span<const uint8_t> children) {
         XMSS_Address node_adrs(adrs);
         node_adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
         node_adrs.set_tree_height(j - 1);

         std::vector<XMSS_Address> node_addrs(count, node_adrs);
         for(uint32_t i = 0; i != count; ++i) {
            node_addrs[i].set_tree_index(first_t + i);
         }

         XMSS_Common_Ops::randomize_tree_hashes(out, children, node_addrs, builder.public_seed(), hash, n);
      };

   return Merkle_Tree_Builder(static_cast<uint32_t>(height), n, LEAF_BATCH, std::move(leaf_fn), std::move(node_fn));
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

   BOTAN_ASSERT_NOMSG(len > 0 && sks.size() == count * n && count % len == 0);

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
