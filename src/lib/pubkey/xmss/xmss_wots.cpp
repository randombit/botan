/*
 * XMSS WOTS Public and Private Key
 *
 * A Winternitz One Time Signature public/private key for use with
 * Extended Hash-Based Signatures.
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 *     2023           René Meusel - Rohde & Schwarz Cybersecurity
 *     2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots.h>

#include <botan/mem_ops.h>
#include <botan/internal/xmss_address.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_tools.h>

namespace Botan {

namespace {

/**
* Algorithm 1 (base_w) followed by the WOTS+ checksum, as used by the
* signing and verification routines in RFC 8391. The result is a single
* buffer of length params.len() holding the len_1 base-w digits of the
* message followed by the len_2 base-w digits of the checksum.
*/
secure_vector<uint8_t> base_w_with_checksum(const XMSS_WOTS_Parameters& params, std::span<const uint8_t> input) {
   const size_t len_1 = params.len_1();
   const size_t len_2 = params.len_2();
   const size_t lg_w = params.lg_w();
   const uint8_t mask = static_cast<uint8_t>(params.wots_parameter() - 1);

   BOTAN_ASSERT_NOMSG(input.size() * 8 >= len_1 * lg_w);

   secure_vector<uint8_t> result(len_1 + len_2);

   size_t in = 0;
   size_t total = 0;
   size_t bits = 0;
   for(size_t i = 0; i < len_1; ++i) {
      if(bits == 0) {
         total = input[in++];
         bits = 8;
      }
      bits -= lg_w;
      result[i] = static_cast<uint8_t>((total >> bits) & mask);
   }

   size_t csum = 0;
   for(size_t i = 0; i < len_1; ++i) {
      csum += params.wots_parameter() - 1 - result[i];
   }

   for(size_t i = 0; i < len_2; ++i) {
      const size_t shift = lg_w * (len_2 - 1 - i);
      result[len_1 + i] = static_cast<uint8_t>((csum >> shift) & mask);
   }

   return result;
}

/**
 * Algorithm 2 applied to the chains of a single WOTS+ key
 *
 * @param params The WOTS parameters to use
 * @param[in,out] nodes The chain nodes, transformed in place
 * @param from Per chain, the first hash address to apply
 * @param to Per chain, the hash address to stop at (exclusive)
 * @param adrs The OTS hash address of the key
 * @param seed A seed.
 * @param hash Instance of XMSS_Hash, that may only be used by the thread
 *             executing chains.
 **/
void chains(const XMSS_WOTS_Parameters& params,
            wots_keysig_t& nodes,
            std::span<const uint8_t> from,
            std::span<const uint8_t> to,
            const XMSS_Address& adrs,
            std::span<const uint8_t> seed,
            XMSS_Hash& hash) {
   const size_t len = nodes.size();
   const size_t n = hash.output_length();

   std::vector<XMSS_Address> addrs(len, adrs);
   secure_vector<uint8_t> flat(len * n);
   for(size_t i = 0; i < len; ++i) {
      BOTAN_ASSERT_NOMSG(nodes[i].size() == n);
      addrs[i].set_chain_address(static_cast<uint32_t>(i));
      copy_mem(std::span(flat).subspan(i * n, n), nodes[i]);
   }

   xmss_wots_chains(params, flat, from, to, addrs, seed, hash);

   for(size_t i = 0; i < len; ++i) {
      copy_mem(nodes[i], std::span(flat).subspan(i * n, n));
   }
}

}  // namespace

/*
 * Note that RFC 8391 defines this algorithm recursively (building up the
 * iterations before any calculation) using 'steps' as the iterator and a
 * recursion base with 'steps == 0'.
 * Instead, we implement it iteratively using 's' as iterator. This makes
 * 'set_hash_address(s)' equivalent to 'ADRS.setHashAddress(i + s - 1)'.
 */
void xmss_wots_chains(const XMSS_WOTS_Parameters& params,
                      std::span<uint8_t> nodes,
                      std::span<const uint8_t> from,
                      std::span<const uint8_t> to,
                      std::span<XMSS_Address> addrs,
                      std::span<const uint8_t> seed,
                      XMSS_Hash& hash) {
   const size_t count = addrs.size();
   const size_t n = hash.output_length();

   BOTAN_ASSERT_NOMSG(nodes.size() == count * n);
   BOTAN_ASSERT_NOMSG(from.size() == count && to.size() == count);

   for(size_t i = 0; i < count; ++i) {
      BOTAN_ASSERT_NOMSG(to[i] < params.wots_parameter());
   }

   // Each step computes the bitmask and the key of every active chain
   // with a single PRF batch. The addresses differ only in the key/mask
   // mode, so a second set of addresses in mask mode is kept alongside.
   std::vector<XMSS_Address> mask_addrs(addrs.begin(), addrs.end());
   for(size_t i = 0; i < count; ++i) {
      mask_addrs[i].set_key_mask_mode(XMSS_Address::Key_Mask::Mask_Mode);
      addrs[i].set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);
   }

   // Lane descriptors for the case that every chain is active; the
   // bitmasks are lanes [0, count) and the keys lanes [count, 2*count).
   // The address bytes are updated in place each step so the spans
   // stay valid throughout. The filtered variants are subsets of these.
   secure_vector<uint8_t> prf_outputs(2 * count * n);
   std::vector<std::span<uint8_t>> all_prf_out(2 * count);
   std::vector<std::span<const uint8_t>> all_prf_in(2 * count);
   std::vector<std::span<uint8_t>> all_node(count);
   std::vector<std::span<const uint8_t>> all_key(count);
   std::vector<std::span<const uint8_t>> all_node_in(count);

   for(size_t i = 0; i < count; ++i) {
      all_prf_out[i] = std::span(prf_outputs).subspan(i * n, n);
      all_prf_out[count + i] = std::span(prf_outputs).subspan((count + i) * n, n);
      all_prf_in[i] = mask_addrs[i].bytes();
      all_prf_in[count + i] = addrs[i].bytes();
      all_node[i] = nodes.subspan(i * n, n);
      all_key[i] = all_prf_out[count + i];
      all_node_in[i] = all_node[i];
   }

   std::vector<size_t> active;
   std::vector<std::span<uint8_t>> prf_out;
   std::vector<std::span<const uint8_t>> prf_in;
   std::vector<std::span<uint8_t>> node_out;
   std::vector<std::span<const uint8_t>> keys;
   std::vector<std::span<const uint8_t>> node_in;

   for(size_t s = 0; s + 1 < params.wots_parameter(); ++s) {
      active.clear();
      for(size_t i = 0; i < count; ++i) {
         if(from[i] <= s && s < to[i]) {
            active.push_back(i);
         }
      }
      if(active.empty()) {
         continue;
      }

      for(const size_t i : active) {
         addrs[i].set_hash_address(static_cast<uint32_t>(s));
         mask_addrs[i].set_hash_address(static_cast<uint32_t>(s));
      }

      if(active.size() == count) {
         hash.prf_batch(all_prf_out, seed, all_prf_in);

         // Calculate tmp XOR bitmask, then f(key, tmp XOR bitmask)
         for(size_t i = 0; i < count; ++i) {
            xor_buf(all_node[i], all_prf_out[i]);
         }
         hash.f_batch(all_node, all_key, all_node_in);
      } else {
         prf_out.clear();
         prf_in.clear();
         node_out.clear();
         keys.clear();
         node_in.clear();

         for(const size_t i : active) {
            prf_out.push_back(all_prf_out[i]);
            prf_in.push_back(all_prf_in[i]);
         }
         for(const size_t i : active) {
            prf_out.push_back(all_prf_out[count + i]);
            prf_in.push_back(all_prf_in[count + i]);
         }
         hash.prf_batch(prf_out, seed, prf_in);

         for(const size_t i : active) {
            xor_buf(all_node[i], all_prf_out[i]);
            node_out.push_back(all_node[i]);
            keys.push_back(all_key[i]);
            node_in.push_back(all_node_in[i]);
         }
         hash.f_batch(node_out, keys, node_in);
      }
   }
}

XMSS_WOTS_PublicKey::XMSS_WOTS_PublicKey(XMSS_WOTS_Parameters params,
                                         std::span<const uint8_t> public_seed,
                                         wots_keysig_t signature,
                                         const secure_vector<uint8_t>& msg,
                                         XMSS_Address adrs,
                                         XMSS_Hash& hash) :
      XMSS_WOTS_Base(params, std::move(signature)) {
   const secure_vector<uint8_t> msg_digest = base_w_with_checksum(m_params, msg);
   const std::vector<uint8_t> to(m_params.len(), static_cast<uint8_t>(m_params.wots_parameter() - 1));

   chains(m_params, m_key_data, msg_digest, to, adrs, public_seed, hash);
}

wots_keysig_t XMSS_WOTS_PrivateKey::sign(const secure_vector<uint8_t>& msg,
                                         std::span<const uint8_t> public_seed,
                                         XMSS_Address adrs,
                                         XMSS_Hash& hash) {
   const secure_vector<uint8_t> msg_digest = base_w_with_checksum(m_params, msg);
   auto sig = this->key_data();

   const std::vector<uint8_t> from(m_params.len(), 0);
   chains(m_params, sig, from, msg_digest, adrs, public_seed, hash);

   return sig;
}

XMSS_WOTS_PrivateKey::XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters params,
                                           std::span<const uint8_t> public_seed,
                                           std::span<const uint8_t> private_seed,
                                           XMSS_Address adrs,
                                           XMSS_Hash& hash) :
      XMSS_WOTS_Base(params) {
   const size_t len = m_params.len();
   const size_t n = hash.output_length();

   m_key_data.resize(len);

   std::vector<XMSS_Address> addrs(len, adrs);
   const size_t data_len = public_seed.size() + adrs.size();
   std::vector<uint8_t> data_arena(len * data_len);

   std::vector<std::span<uint8_t>> outputs(len);
   std::vector<std::span<const uint8_t>> data(len);

   for(size_t i = 0; i < len; ++i) {
      addrs[i].set_chain_address(static_cast<uint32_t>(i));

      const auto slot = std::span(data_arena).subspan(i * data_len, data_len);
      copy_mem(slot.first(public_seed.size()), public_seed);
      copy_mem(slot.subspan(public_seed.size()), addrs[i].bytes());

      m_key_data[i].resize(n);
      outputs[i] = std::span(m_key_data[i]);
      data[i] = slot;
   }

   hash.prf_keygen_batch(outputs, private_seed, data);
}

// Constructor for legacy XMSS_PrivateKeys
XMSS_WOTS_PrivateKey::XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters params,
                                           std::span<const uint8_t> private_seed,
                                           XMSS_Address adrs,
                                           XMSS_Hash& hash) :
      XMSS_WOTS_Base(params) {
   m_key_data.resize(m_params.len());

   secure_vector<uint8_t> r;
   hash.prf(r, private_seed, adrs.bytes());

   for(size_t i = 0; i < m_params.len(); ++i) {
      xmss_concat<size_t>(m_key_data[i], i, 32);
      hash.prf(m_key_data[i], r, m_key_data[i]);
   }
}

}  // namespace Botan
