/*
 * XMSS Common Ops
 * Operations shared by XMSS signature generation and verification operations.
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_common_ops.h>

#include <botan/mem_ops.h>
#include <botan/internal/xmss_hash.h>

namespace Botan {

void XMSS_Common_Ops::randomize_tree_hash(secure_vector<uint8_t>& result,
                                          const secure_vector<uint8_t>& left,
                                          const secure_vector<uint8_t>& right,
                                          XMSS_Address adrs,
                                          const secure_vector<uint8_t>& seed,
                                          XMSS_Hash& hash,
                                          const XMSS_Parameters& params) {
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

   secure_vector<uint8_t> concat_xor(params.element_size() * 2);
   for(size_t i = 0; i < left.size(); i++) {
      concat_xor[i] = left[i] ^ bitmask_l[i];
      concat_xor[i + left.size()] = right[i] ^ bitmask_r[i];
   }

   hash.h(result, key, concat_xor);
}

void XMSS_Common_Ops::create_l_tree(secure_vector<uint8_t>& result,
                                    const wots_keysig_t& pk,
                                    XMSS_Address adrs,
                                    const secure_vector<uint8_t>& seed,
                                    XMSS_Hash& hash,
                                    const XMSS_Parameters& params) {
   const size_t n = params.element_size();
   BOTAN_ASSERT_NOMSG(pk.size() == params.len());

   secure_vector<uint8_t> flat(pk.size() * n);
   for(size_t i = 0; i < pk.size(); ++i) {
      BOTAN_ASSERT_NOMSG(pk[i].size() == n);
      copy_mem(std::span(flat).subspan(i * n, n), pk[i]);
   }

   result.resize(n);
   create_l_trees(result, flat, std::span(&adrs, 1), seed, hash, params);
}

void XMSS_Common_Ops::create_l_trees(std::span<uint8_t> leaves,
                                     std::span<uint8_t> pks,
                                     std::span<XMSS_Address> addrs,
                                     std::span<const uint8_t> seed,
                                     XMSS_Hash& hash,
                                     const XMSS_Parameters& params) {
   const size_t count = addrs.size();
   const size_t n = params.element_size();
   const size_t stride = params.len() * n;

   BOTAN_ASSERT_NOMSG(leaves.size() == count * n);
   BOTAN_ASSERT_NOMSG(pks.size() == count * stride);

   if(count == 0) {
      return;
   }

   const size_t adrs_len = addrs[0].size();

   for(auto& adrs : addrs) {
      adrs.set_tree_height(0);
   }

   // Scratch for one level's batched randomized tree hashes: per node
   // pair the three PRF addresses (key, bitmask left/right), the key,
   // and the masked concatenation of both child nodes
   const size_t max_pairs = count * (params.len() / 2);
   std::vector<uint8_t> adrs_buf(3 * max_pairs * adrs_len);
   secure_vector<uint8_t> keys(max_pairs * n);
   secure_vector<uint8_t> concat(max_pairs * 2 * n);

   std::vector<std::span<uint8_t>> prf_outs(3 * max_pairs);
   std::vector<std::span<const uint8_t>> prf_ins(3 * max_pairs);
   std::vector<std::span<uint8_t>> h_outs(max_pairs);
   std::vector<std::span<const uint8_t>> h_keys(max_pairs);
   std::vector<std::span<const uint8_t>> h_ins(max_pairs);

   auto node = [&](size_t k, size_t i) { return pks.subspan(k * stride + i * n, n); };

   size_t l = params.len();

   while(l > 1) {
      const size_t pairs = l >> 1;
      const size_t total = count * pairs;

      // Compute the keys and both bitmasks of all of this level's node
      // pairs with one PRF batch, the bitmasks landing in the buffer
      // that the child nodes are then XORed into
      for(size_t k = 0; k < count; k++) {
         for(size_t i = 0; i < pairs; i++) {
            const size_t p = k * pairs + i;
            addrs[k].set_tree_index(static_cast<uint32_t>(i));
            const auto adrs_lane = [&](size_t lane, XMSS_Address::Key_Mask mode) {
               addrs[k].set_key_mask_mode(mode);
               const auto dest = std::span(adrs_buf).subspan(lane * adrs_len, adrs_len);
               copy_mem(dest, addrs[k].bytes());
               prf_ins[lane] = dest;
            };
            adrs_lane(3 * p, XMSS_Address::Key_Mask::Key_Mode);
            adrs_lane(3 * p + 1, XMSS_Address::Key_Mask::Mask_MSB_Mode);
            adrs_lane(3 * p + 2, XMSS_Address::Key_Mask::Mask_LSB_Mode);

            prf_outs[3 * p] = std::span(keys).subspan(p * n, n);
            prf_outs[3 * p + 1] = std::span(concat).subspan(p * 2 * n, n);
            prf_outs[3 * p + 2] = std::span(concat).subspan(p * 2 * n + n, n);
         }
      }
      hash.prf_batch(std::span(prf_outs).first(3 * total), seed, std::span(prf_ins).first(3 * total));

      for(size_t k = 0; k < count; k++) {
         for(size_t i = 0; i < pairs; i++) {
            const size_t p = k * pairs + i;
            xor_buf(std::span(concat).subspan(p * 2 * n, n), node(k, 2 * i));
            xor_buf(std::span(concat).subspan(p * 2 * n + n, n), node(k, 2 * i + 1));
            h_outs[p] = node(k, i);
            h_keys[p] = std::span(keys).subspan(p * n, n);
            h_ins[p] = std::span(concat).subspan(p * 2 * n, 2 * n);
         }
      }
      hash.h_batch(std::span(h_outs).first(total), std::span(h_keys).first(total), std::span(h_ins).first(total));

      if((l & 0x01) == 0x01) {
         for(size_t k = 0; k < count; k++) {
            copy_mem(node(k, l >> 1), node(k, l - 1));
         }
      }
      l = (l >> 1) + (l & 0x01);
      for(auto& adrs : addrs) {
         adrs.set_tree_height(adrs.get_tree_height() + 1);
      }
   }

   for(size_t k = 0; k < count; k++) {
      copy_mem(leaves.subspan(k * n, n), node(k, 0));
   }
}

}  // namespace Botan
