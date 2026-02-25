/*
 * XMSS^MT Verification Operation
 * Provides signature verification capabilities for Extended Hash-Based
 * Signatures (XMSS^MT).
 *
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmssmt_verification_operation.h>

#include <botan/internal/xmss_tools.h>
#include <array>

namespace Botan {

XMSSMT_Verification_Operation::XMSSMT_Verification_Operation(const XMSSMT_PublicKey& public_key) :
      m_pub_key(public_key),
      m_hash(public_key.xmssmt_parameters().hash_function_name(), public_key.xmssmt_parameters().hash_id_size()),
      m_msg_buf(0) {}

bool XMSSMT_Verification_Operation::verify(const XMSSMT_Signature& sig,
                                           const secure_vector<uint8_t>& msg,
                                           const XMSSMT_PublicKey& public_key) {
   const XMSSMT_Parameters& params = public_key.xmssmt_parameters();
   BOTAN_ASSERT_NOMSG(params.xmss_tree_height() > 0 && params.xmss_tree_height() < 32);
   XMSS_Address adrs;
   secure_vector<uint8_t> index_bytes;
   xmss_concat(index_bytes, sig.unused_leaf_index(), params.element_size());
   const secure_vector<uint8_t> msg_digest = m_hash.h_msg(sig.randomness(), public_key.root(), index_bytes, msg);

   uint64_t idx_tree = sig.unused_leaf_index();

   adrs.set_layer_addr(0);
   adrs.set_tree_addr(idx_tree);

   secure_vector<uint8_t> node = msg_digest;

   for(size_t i = 0; i < params.tree_layers(); i++) {
      const uint32_t idx_leaf = (idx_tree & ((1 << params.xmss_tree_height()) - 1));
      idx_tree = idx_tree >> params.xmss_tree_height();

      adrs.set_layer_addr(static_cast<uint32_t>(i));
      adrs.set_tree_addr(idx_tree);

      node = XMSS_Core_Ops::root_from_signature(idx_leaf,
                                                sig.tree(i),
                                                node,
                                                adrs,
                                                public_key.public_seed(),
                                                m_hash,
                                                params.element_size(),
                                                params.xmss_tree_height(),
                                                params.len(),
                                                params.ots_oid());
   }

   return (node == public_key.root());
}

// FIXME: XMSS signature verification requires the "randomness" parameter out
// of the XMSS signature, which is part of the prefix that is hashed before
// msg. Since the signature is unknown till sign() is called all message
// content has to be buffered. For large messages this can be inconvenient or
// impossible.
// Possible solution: Change PK_Ops::Verification interface to take the
// signature as constructor argument, make sign a parameterless member call.
void XMSSMT_Verification_Operation::update(std::span<const uint8_t> input) {
   m_msg_buf.insert(m_msg_buf.end(), input.begin(), input.end());
}

bool XMSSMT_Verification_Operation::is_valid_signature(std::span<const uint8_t> sig) {
   try {
      const XMSSMT_Signature signature(m_pub_key.xmssmt_parameters().oid(), sig);
      const bool result = verify(signature, m_msg_buf, m_pub_key);
      m_msg_buf.clear();
      return result;
   } catch(...) {
      m_msg_buf.clear();
      return false;
   }
}

}  // namespace Botan
