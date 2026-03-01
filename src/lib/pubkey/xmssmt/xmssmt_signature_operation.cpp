/*
 * XMSS^MT Signature Operation
 * Signature generation operation for Extended Hash-Based Signatures (XMSS^MT) as
 * defined in:
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmssmt_signature_operation.h>

#include <botan/internal/xmss_tools.h>

namespace Botan {

XMSSMT_Signature_Operation::XMSSMT_Signature_Operation(const XMSSMT_PrivateKey& private_key) :
      m_priv_key(private_key),
      m_hash(private_key.xmssmt_parameters().hash_function_name(), private_key.xmssmt_parameters().hash_id_size()),
      m_randomness(0),
      m_leaf_idx(0),
      m_is_initialized(false) {}

XMSS_TreeSignature XMSSMT_Signature_Operation::generate_tree_signature(const secure_vector<uint8_t>& msg,
                                                                       XMSS_Address& adrs,
                                                                       uint32_t idx_leaf) {
   XMSS_TreeSignature result;

   result.ots_signature =
      m_priv_key.wots_private_key_for(adrs, m_hash).sign(msg, m_priv_key.public_seed(), adrs, m_hash);

   result.authentication_path = build_auth_path(idx_leaf, adrs);
   return result;
}

secure_vector<uint8_t> XMSSMT_Signature_Operation::root_from_signature(const XMSS_TreeSignature& tree_sig,
                                                                       const secure_vector<uint8_t>& msg,
                                                                       const XMSS_Address& adrs,
                                                                       uint32_t leaf_idx) {
   const XMSSMT_Parameters& params = m_priv_key.xmssmt_parameters();
   return XMSS_Core_Ops::root_from_signature(leaf_idx,
                                             tree_sig,
                                             msg,
                                             adrs,
                                             m_priv_key.public_seed(),
                                             m_hash,
                                             params.element_size(),
                                             params.xmss_tree_height(),
                                             params.len(),
                                             params.ots_oid());
}

size_t XMSSMT_Signature_Operation::signature_length() const {
   const auto& params = m_priv_key.xmssmt_parameters();
   return params.encoded_idx_size() + params.element_size() +
          params.tree_layers() * (params.len() + params.xmss_tree_height()) * params.element_size();
}

wots_keysig_t XMSSMT_Signature_Operation::build_auth_path(uint32_t idx_leaf, const XMSS_Address& adrs) {
   const auto& params = m_priv_key.xmssmt_parameters();
   wots_keysig_t auth_path(params.xmss_tree_height());

   for(size_t j = 0; j < params.xmss_tree_height(); j++) {
      const uint32_t k = (idx_leaf / (static_cast<uint32_t>(1) << j)) ^ 0x01;
      auth_path[j] = m_priv_key.tree_hash(k * (static_cast<uint32_t>(1) << j), j, adrs, m_hash);
   }

   return auth_path;
}

void XMSSMT_Signature_Operation::update(std::span<const uint8_t> input) {
   initialize();
   m_hash.h_msg_update(input);
}

std::vector<uint8_t> XMSSMT_Signature_Operation::sign(RandomNumberGenerator& /*rng*/) {
   initialize();

   const auto msg_hash = m_hash.h_msg_final();

   const XMSSMT_Parameters& params = m_priv_key.xmssmt_parameters();
   BOTAN_ASSERT_NOMSG(params.xmss_tree_height() > 0 && params.xmss_tree_height() < 32);
   std::vector<XMSS_TreeSignature> tree_sigs;

   uint64_t idx_tree = m_leaf_idx;
   secure_vector<uint8_t> node = msg_hash;
   for(size_t i = 0; i < params.tree_layers(); i++) {
      const uint32_t idx_leaf = (idx_tree & ((1 << params.xmss_tree_height()) - 1));
      idx_tree = idx_tree >> params.xmss_tree_height();

      XMSS_Address adrs;
      adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
      adrs.set_layer_addr(static_cast<uint32_t>(i));
      adrs.set_tree_addr(idx_tree);
      adrs.set_ots_address(idx_leaf);
      tree_sigs.push_back(generate_tree_signature(node, adrs, idx_leaf));

      // compute the root node of the current XMSS tree (not for the top level tree)
      if(i < params.tree_layers() - 1) {
         // use the auth path to compute the root node efficiently
         node = root_from_signature(tree_sigs[i], node, adrs, idx_leaf);
      }
   }

   const XMSSMT_Signature sig(params, m_leaf_idx, m_randomness, tree_sigs);
   m_is_initialized = false;
   return sig.bytes();
}

void XMSSMT_Signature_Operation::initialize() {
   // return if we already initialized and reserved a leaf index for signing.
   if(m_is_initialized) {
      return;
   }

   secure_vector<uint8_t> index_bytes;
   // reserve leaf index so it can not be reused by another signature
   // operation using the same private key.
   m_leaf_idx = m_priv_key.reserve_unused_leaf_index();

   // write prefix for message hashing into buffer.
   xmss_concat(index_bytes, m_leaf_idx, 32);
   m_hash.prf(m_randomness, m_priv_key.prf_value(), index_bytes);
   index_bytes.clear();
   xmss_concat(index_bytes, m_leaf_idx, m_priv_key.xmssmt_parameters().element_size());
   m_hash.h_msg_init(m_randomness, m_priv_key.root(), index_bytes);
   m_is_initialized = true;
}

AlgorithmIdentifier XMSSMT_Signature_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("XMSSMT"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

}  // namespace Botan
