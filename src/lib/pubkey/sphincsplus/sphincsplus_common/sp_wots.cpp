/*
* WOTS+ - Winternitz One Time Signature Plus Scheme (FIPS 205, Section 5)
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/sp_wots.h>

#include <botan/mem_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/sp_hash.h>

namespace Botan {
namespace {

/**
 * FIPS 205, Algorithm 4: base_2^b for WOTS+
 *
 * Interprets an array of bytes as integers in base w = 2^b.
 * This only works when lg_w is a divisor of 8.
 */
void base_2_b(std::span<WotsHashIndex> output, std::span<const uint8_t> input, const Sphincs_Parameters& params) {
   BOTAN_ASSERT_NOMSG(output.size() <= 8 * input.size() / params.log_w());

   size_t input_offset = 0;
   uint8_t current_byte = 0;
   uint32_t remaining_bits_in_current_byte = 0;

   for(auto& out : output) {
      if(remaining_bits_in_current_byte == 0) {
         current_byte = input[input_offset];
         ++input_offset;
         remaining_bits_in_current_byte = 8;
      }
      remaining_bits_in_current_byte -= params.log_w();
      out = WotsHashIndex((current_byte >> remaining_bits_in_current_byte) & (params.w() - 1));
   }
}

/**
 * Computes the WOTS+ checksum over a message (in base_2^b).
 * Corresponds to FIPS 205, Algorithm 7 or 8, Step 7.
 */
void wots_checksum(std::span<WotsHashIndex> output,
                   std::span<const WotsHashIndex> msg_base_w,
                   const Sphincs_Parameters& params) {
   uint32_t csum = 0;

   // Compute checksum.
   for(auto wots_hash_index : msg_base_w) {
      csum += params.w() - 1 - wots_hash_index.get();
   }

   // Convert checksum to base_w.
   csum = csum << ((8 - ((params.wots_len_2() * params.log_w()) % 8)) % 8);

   std::array<uint8_t, 4> csum_bytes{};
   store_be(csum, csum_bytes.data());

   const size_t csum_bytes_size = params.wots_checksum_bytes();
   BOTAN_ASSERT_NOMSG(csum_bytes.size() >= csum_bytes_size);
   base_2_b(output, std::span(csum_bytes).last(csum_bytes_size), params);
}

}  // namespace

std::vector<WotsHashIndex> chain_lengths(const SphincsTreeNode& msg, const Sphincs_Parameters& params) {
   std::vector<WotsHashIndex> result(params.wots_len_1() + params.wots_len_2());

   auto msg_base_w = std::span(result).first(params.wots_len_1());
   auto checksum_base_w = std::span(result).last(params.wots_len_2());

   base_2_b(msg_base_w, msg.get(), params);
   wots_checksum(checksum_base_w, msg_base_w, params);

   return result;
}

WotsPublicKey wots_public_key_from_signature(const SphincsTreeNode& hashed_message,
                                             StrongSpan<const WotsSignature> signature,
                                             const Sphincs_Address& address,
                                             const Sphincs_Parameters& params,
                                             Sphincs_Hash_Functions& hashes) {
   const std::vector<WotsHashIndex> lengths = chain_lengths(hashed_message, params);
   const size_t len = params.wots_len();
   const size_t n = params.n();

   // The chains start with the nodes in the signature
   WotsPublicKey pk_buffer(len * n);
   std::copy(signature.begin(), signature.end(), pk_buffer.begin());
   const std::span<uint8_t> pk_bytes(pk_buffer.get());

   std::vector<Sphincs_Address> chain_addrs(len, address);
   for(size_t i = 0; i != len; ++i) {
      chain_addrs[i].set_chain_address(WotsChainIndex(static_cast<uint32_t>(i)));
   }

   std::vector<Sphincs_Address> addrs;
   std::vector<std::span<uint8_t>> outs;
   std::vector<std::span<const uint8_t>> ins;
   addrs.reserve(len);
   outs.reserve(len);
   ins.reserve(len);

   // Walk the chains in lock-step; chain i joins in once the step counter
   // reaches its position in the signature
   for(WotsHashIndex k(0); k < params.w() - 1; k++) {
      addrs.clear();
      outs.clear();
      ins.clear();

      for(size_t i = 0; i != len; ++i) {
         if(lengths[i] <= k) {
            chain_addrs[i].set_hash_address(k);
            addrs.push_back(chain_addrs[i]);
            const auto node = pk_bytes.subspan(i * n, n);
            outs.push_back(node);
            ins.push_back(node);
         }
      }

      hashes.T_batch(outs, addrs, ins);
   }

   return pk_buffer;
}

void wots_sign_and_pkgen(StrongSpan<WotsSignature> sig_out,
                         std::span<uint8_t> leaves_out,
                         const SphincsSecretSeed& secret_seed,
                         TreeNodeIndex first_leaf_idx,
                         size_t leaf_count,
                         std::optional<TreeNodeIndex> sign_leaf_idx,
                         const std::vector<WotsHashIndex>& wots_steps,
                         Sphincs_Address& leaf_addr,
                         Sphincs_Address& pk_addr,
                         const Sphincs_Parameters& params,
                         Sphincs_Hash_Functions& hashes) {
   // `wots_steps` are needed only if `sign_leaf_idx` is set
   BOTAN_ASSERT_NOMSG(!sign_leaf_idx.has_value() || wots_steps.size() == params.wots_len());
   BOTAN_ASSERT_NOMSG(pk_addr.get_type() == Sphincs_Address_Type::WotsPublicKeyCompression);
   BOTAN_ASSERT_NOMSG(leaves_out.size() == leaf_count * params.n());

   const size_t len = params.wots_len();
   const size_t n = params.n();
   const size_t lanes = leaf_count * len;

   // WOTS public key buffers of all leaves, one lane per chain
   secure_vector<uint8_t> pk_buffers(leaf_count * params.wots_bytes());

   // The chains share their leaf's address except for their chain field
   leaf_addr.set_type(Sphincs_Address_Type::WotsKeyGeneration);
   leaf_addr.set_hash_address(WotsHashIndex(0));

   std::vector<Sphincs_Address> addrs;
   addrs.reserve(lanes);
   std::vector<std::span<uint8_t>> nodes(lanes);
   std::vector<std::span<const uint8_t>> cnodes(lanes);
   for(size_t j = 0; j != leaf_count; ++j) {
      leaf_addr.set_keypair_address(first_leaf_idx + static_cast<uint32_t>(j));
      for(size_t i = 0; i != len; ++i) {
         addrs.push_back(leaf_addr);
         addrs.back().set_chain_address(WotsChainIndex(static_cast<uint32_t>(i)));
         const auto node = std::span(pk_buffers).subspan((j * len + i) * n, n);
         nodes[j * len + i] = node;
         cnodes[j * len + i] = node;
      }
   }

   // Start each chain with its secret seed
   hashes.PRF_batch(nodes, secret_seed, addrs);

   for(auto& addr : addrs) {
      addr.set_type(Sphincs_Address_Type::WotsHash);
   }

   const bool signing_in_batch = sign_leaf_idx.has_value() && sign_leaf_idx.value() >= first_leaf_idx &&
                                 sign_leaf_idx.value() < first_leaf_idx + static_cast<uint32_t>(leaf_count);
   const size_t sign_j = signing_in_batch ? static_cast<size_t>(sign_leaf_idx.value().get() - first_leaf_idx.get()) : 0;

   // Iterate down all chains of all leaves in lock-step
   for(WotsHashIndex k(0);; k++) {
      // Check for values that need to be saved as a part of the WOTS signature
      if(signing_in_batch) {
         for(size_t i = 0; i != len; ++i) {
            if(wots_steps[i] == k) {
               copy_mem(sig_out.get().subspan(i * n, n), nodes[sign_j * len + i]);
            }
         }
      }

      // Check if the top of the chains was hit
      if(k == params.w() - 1) {
         break;
      }

      for(auto& addr : addrs) {
         addr.set_hash_address(k);
      }

      hashes.T_batch(nodes, addrs, cnodes);
   }

   // Do the final thashes compressing each leaf's WOTS public key
   std::vector<Sphincs_Address> pk_addrs;
   pk_addrs.reserve(leaf_count);
   std::vector<std::span<uint8_t>> leaf_outs(leaf_count);
   std::vector<std::span<const uint8_t>> pk_spans(leaf_count);
   for(size_t j = 0; j != leaf_count; ++j) {
      pk_addr.set_keypair_address(first_leaf_idx + static_cast<uint32_t>(j));
      pk_addrs.push_back(pk_addr);
      leaf_outs[j] = leaves_out.subspan(j * n, n);
      pk_spans[j] = std::span(pk_buffers).subspan(j * params.wots_bytes(), params.wots_bytes());
   }
   hashes.T_batch(leaf_outs, pk_addrs, pk_spans);
}

}  // namespace Botan
