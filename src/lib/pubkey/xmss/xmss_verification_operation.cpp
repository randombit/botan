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

#include <botan/internal/xmss_core.h>
#include <botan/internal/xmss_tools.h>
#include <array>

namespace Botan {

XMSS_Verification_Operation::XMSS_Verification_Operation(const XMSS_PublicKey& public_key) :
      m_pub_key(public_key), m_hash(public_key.xmss_parameters()), m_msg_buf(0) {}

bool XMSS_Verification_Operation::verify(const XMSS_Signature& sig,
                                         const secure_vector<uint8_t>& msg,
                                         const XMSS_PublicKey& public_key) {
   const XMSS_Parameters& params = public_key.xmss_parameters();
   const XMSS_Address adrs;
   secure_vector<uint8_t> index_bytes;
   xmss_concat(index_bytes, sig.unused_leaf_index(), m_pub_key.xmss_parameters().element_size());
   const secure_vector<uint8_t> msg_digest = m_hash.h_msg(sig.randomness(), public_key.root(), index_bytes, msg);

   const secure_vector<uint8_t> node =
      XMSS_Core_Ops::root_from_signature(static_cast<uint32_t>(sig.unused_leaf_index()),
                                         sig.tree(),
                                         msg_digest,
                                         adrs,
                                         public_key.public_seed(),
                                         m_hash,
                                         params.element_size(),
                                         params.tree_height(),
                                         params.len(),
                                         params.ots_oid());

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
      const XMSS_Signature signature(m_pub_key.xmss_parameters().oid(), sig);
      const bool result = verify(signature, m_msg_buf, m_pub_key);
      m_msg_buf.clear();
      return result;
   } catch(...) {
      m_msg_buf.clear();
      return false;
   }
}

}  // namespace Botan
