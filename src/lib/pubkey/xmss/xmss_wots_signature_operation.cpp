/**
 * XMSS WOTS Signature Operation
 * Signature generation operation for Winternitz One Time Signatures for use
 * in Extended Hash-Based Signatures (XMSS).
 *
 * This operation is not intended for stand-alone use and thus not registered
 * in the Botan algorithm registry.
 *
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots_signature_operation.h>

namespace Botan {

XMSS_WOTS_Signature_Operation::XMSS_WOTS_Signature_Operation(
   const XMSS_WOTS_Addressed_PrivateKey& private_key)
   : XMSS_WOTS_Common_Ops(private_key.private_key().wots_parameters().oid()),
     m_priv_key(private_key),
     m_msg_buf(0)
   {
   m_msg_buf.reserve(
      m_priv_key.private_key().wots_parameters().element_size());
   }

void
XMSS_WOTS_Signature_Operation::update(const uint8_t msg[], size_t msg_len)
   {
   BOTAN_ASSERT(msg_len == m_priv_key.private_key().wots_parameters().
                           element_size() &&
                m_msg_buf.size() == 0,
                "XMSS WOTS only supports one message part of size n.");

   for(size_t i = 0; i < msg_len; i++)
      m_msg_buf.push_back(msg[i]);
   }

secure_vector<uint8_t>
XMSS_WOTS_Signature_Operation::sign(RandomNumberGenerator&)
   {
   secure_vector<uint8_t> result(0);
   result.reserve(m_wots_params.len() * m_wots_params.element_size());
   XMSS_WOTS_PrivateKey& priv_key = m_priv_key.private_key();
   for(const auto& node : priv_key.sign(m_msg_buf, m_priv_key.address()))
      {
      std::copy(node.begin(), node.end(), std::back_inserter(result));
      }

   return result;
   }

}
