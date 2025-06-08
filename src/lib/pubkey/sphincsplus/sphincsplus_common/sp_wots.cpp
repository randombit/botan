/*
* WOTS+ - Winternitz One Time Signature Plus Scheme (FIPS 205, Section 5)
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/sp_wots.h>

#include <botan/internal/sp_hash.h>
#include <botan/internal/stl_util.h>

namespace Botan {
namespace {

/**
 * @brief FIPS 205, Algorithm 5: chain
 *
 * Computes a WOTS+ hash chain for @p steps steps beginning with value
 * @p wots_chain_key at index @p start.
 */
void chain(StrongSpan<WotsPublicKeyNode> out,
           StrongSpan<const WotsNode> wots_chain_key,
           WotsHashIndex start,
           uint8_t steps,
           Sphincs_Address& addr,
           Sphincs_Hash_Functions& hashes,
           const Sphincs_Parameters& params) {
   // Initialize out with the value at position 'start'.
   std::copy(wots_chain_key.begin(), wots_chain_key.end(), out.begin());

   // Iterate 'steps' calls to the hash function.
   for(WotsHashIndex i = start; i < (start + steps) && i < params.w(); i++) {
      addr.set_hash_address(i);
      hashes.T(out, addr, out);
   }
}

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

   std::array<uint8_t, 4> csum_bytes;
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
                                             Sphincs_Address& address,
                                             const Sphincs_Parameters& params,
                                             Sphincs_Hash_Functions& hashes) {
   const std::vector<WotsHashIndex> lengths = chain_lengths(hashed_message, params);
   WotsPublicKey pk_buffer(params.wots_len() * params.n());
   BufferSlicer sig(signature);
   BufferStuffer pk(pk_buffer);

   for(WotsChainIndex i(0); i < params.wots_len(); i++) {
      address.set_chain_address(i);

      // params.w() can be one of {4, 8, 256}
      const WotsHashIndex start_index = lengths[i.get()];
      const uint8_t steps_to_take = static_cast<uint8_t>(params.w() - 1) - start_index.get();

      chain(pk.next<WotsPublicKeyNode>(params.n()),
            sig.take<WotsNode>(params.n()),
            start_index,
            steps_to_take,
            address,
            hashes,
            params);
   }

   return pk_buffer;
}

void wots_sign_and_pkgen(StrongSpan<WotsSignature> sig_out,
                         StrongSpan<SphincsTreeNode> leaf_out,
                         const SphincsSecretSeed& secret_seed,
                         TreeNodeIndex leaf_idx,
                         std::optional<TreeNodeIndex> sign_leaf_idx,
                         const std::vector<WotsHashIndex>& wots_steps,
                         Sphincs_Address& leaf_addr,
                         Sphincs_Address& pk_addr,
                         const Sphincs_Parameters& params,
                         Sphincs_Hash_Functions& hashes) {
   // `wots_steps` are needed only if `sign_leaf_idx` is set
   BOTAN_ASSERT_NOMSG(!sign_leaf_idx.has_value() || wots_steps.size() == params.wots_len());
   BOTAN_ASSERT_NOMSG(pk_addr.get_type() == Sphincs_Address_Type::WotsPublicKeyCompression);

   secure_vector<uint8_t> wots_sig;
   WotsPublicKey wots_pk_buffer(params.wots_bytes());

   BufferStuffer wots_pk(wots_pk_buffer);
   BufferStuffer sig(sig_out);

   leaf_addr.set_keypair_address(leaf_idx);
   pk_addr.set_keypair_address(leaf_idx);

   for(WotsChainIndex i(0); i < params.wots_len(); i++) {
      // If the current leaf is part of the signature wots_k stores the chain index
      //   of the value neccessary for the signature. Otherwise: nullopt (no signature)
      const auto wots_k = [&]() -> std::optional<WotsHashIndex> {
         if(sign_leaf_idx.has_value() && leaf_idx == sign_leaf_idx.value()) {
            return wots_steps[i.get()];
         } else {
            return std::nullopt;
         }
      }();

      // Start with the secret seed
      leaf_addr.set_chain_address(i);
      leaf_addr.set_hash_address(WotsHashIndex(0));
      leaf_addr.set_type(Sphincs_Address_Type::WotsKeyGeneration);

      auto buffer_s = wots_pk.next<WotsNode>(params.n());

      hashes.PRF(buffer_s, secret_seed, leaf_addr);

      leaf_addr.set_type(Sphincs_Address_Type::WotsHash);

      // Iterates down the WOTS chain
      for(WotsHashIndex k(0);; k++) {
         // Check if this is the value that needs to be saved as a part of the WOTS signature
         if(wots_k.has_value() && k == wots_k.value()) {
            std::copy(buffer_s.begin(), buffer_s.end(), sig.next<WotsNode>(params.n()).begin());
         }

         // Check if the top of the chain was hit
         if(k == params.w() - 1) {
            break;
         }

         // Iterate one step on the chain
         leaf_addr.set_hash_address(k);

         hashes.T(buffer_s, leaf_addr, buffer_s);
      }
   }

   // Do the final thash to generate the public keys
   hashes.T(leaf_out, pk_addr, wots_pk_buffer);
}

}  // namespace Botan
