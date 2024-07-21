/*
 * XMSS Verification Operation
 * Provides signature verification capabilities for Extended Hash-Based
 * Signatures (XMSS).
 *
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_verification_operation.h>

#include <botan/internal/xmss_common_ops.h>
#include <botan/internal/xmss_tools.h>
#include <array>

namespace Botan {

XMSS_Verification_Operation::XMSS_Verification_Operation(const XMSS_PublicKey& public_key) :
      m_pub_key(public_key), m_hash(public_key.xmss_parameters()), m_msg_buf(0) {}

secure_vector<uint8_t> XMSS_Verification_Operation::root_from_signature(const XMSS_Signature& sig,
                                                                        const secure_vector<uint8_t>& msg,
                                                                        XMSS_Address& adrs,
                                                                        const secure_vector<uint8_t>& seed) {
   const auto& params = m_pub_key.xmss_parameters();

   const uint32_t next_index = static_cast<uint32_t>(sig.unused_leaf_index());
   adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   adrs.set_ots_address(next_index);

   XMSS_WOTS_PublicKey pub_key_ots(params.ots_oid(), seed, sig.tree().ots_signature, msg, adrs, m_hash);

   adrs.set_type(XMSS_Address::Type::LTree_Address);
   adrs.set_ltree_address(next_index);

   std::array<secure_vector<uint8_t>, 2> node;
   XMSS_Common_Ops::create_l_tree(node[0], pub_key_ots.key_data(), adrs, seed, m_hash, params);

   adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
   adrs.set_tree_index(next_index);

   for(size_t k = 0; k < params.tree_height(); k++) {
      adrs.set_tree_height(static_cast<uint32_t>(k));
      if(((next_index / (static_cast<size_t>(1) << k)) & 0x01) == 0) {
         adrs.set_tree_index(adrs.get_tree_index() >> 1);
         XMSS_Common_Ops::randomize_tree_hash(
            node[1], node[0], sig.tree().authentication_path[k], adrs, seed, m_hash, params);
      } else {
         adrs.set_tree_index((adrs.get_tree_index() - 1) >> 1);
         XMSS_Common_Ops::randomize_tree_hash(
            node[1], sig.tree().authentication_path[k], node[0], adrs, seed, m_hash, params);
      }
      node[0] = node[1];
   }
   return node[0];
}

bool XMSS_Verification_Operation::verify(const XMSS_Signature& sig,
                                         const secure_vector<uint8_t>& msg,
                                         const XMSS_PublicKey& public_key) {
   XMSS_Address adrs;
   secure_vector<uint8_t> index_bytes;
   XMSS_Tools::concat(index_bytes, sig.unused_leaf_index(), m_pub_key.xmss_parameters().element_size());
   secure_vector<uint8_t> msg_digest = m_hash.h_msg(sig.randomness(), public_key.root(), index_bytes, msg);

   secure_vector<uint8_t> node = root_from_signature(sig, msg_digest, adrs, public_key.public_seed());

   return (node == public_key.root());
}

// FIXME: XMSS signature verification requires the "randomness" parameter out
// of the XMSS signature, which is part of the prefix that is hashed before
// msg. Since the signature is unknown till sign() is called all message
// content has to be buffered. For large messages this can be inconvenient or
// impossible.
// Possible solution: Change PK_Ops::Verification interface to take the
// signature as constructor argument, make sign a parameterless member call.
void XMSS_Verification_Operation::update(std::span<const uint8_t> input) {
   m_msg_buf.insert(m_msg_buf.end(), input.begin(), input.end());
}

bool XMSS_Verification_Operation::is_valid_signature(std::span<const uint8_t> sig) {
   try {
      XMSS_Signature signature(m_pub_key.xmss_parameters().oid(), sig);
      bool result = verify(signature, m_msg_buf, m_pub_key);
      m_msg_buf.clear();
      return result;
   } catch(...) {
      m_msg_buf.clear();
      return false;
   }
}

}  // namespace Botan
