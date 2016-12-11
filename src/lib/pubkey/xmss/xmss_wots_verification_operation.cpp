/**
 * XMSS WOTS Verification Operation
 * Provides signature verification capabilities for Winternitz One Time
 * Signatures used in Extended Hash-Based Signatures (XMSS).
 *
 * This operation is not intended for stand-alone use and thus not registered
 * in the Botan algorithm registry.
 *
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots_verification_operation.h>

namespace Botan {

XMSS_WOTS_Verification_Operation::XMSS_WOTS_Verification_Operation(
   const XMSS_WOTS_Addressed_PublicKey& public_key)
   : XMSS_WOTS_Common_Ops(public_key.public_key().wots_parameters().oid()),
     m_pub_key(public_key),
     m_msg_buf(0)
   {
   m_msg_buf.reserve(m_pub_key.public_key().wots_parameters().
                     element_size());
   }

void
XMSS_WOTS_Verification_Operation::update(const uint8_t msg[], size_t msg_len)
   {
   BOTAN_ASSERT(msg_len == m_pub_key.public_key().wots_parameters().
                           element_size() &&
                m_msg_buf.size() == 0,
                "XMSS WOTS only supports one message part of size n.");

   for(size_t i = 0; i < msg_len; i++)
      {
      m_msg_buf.push_back(msg[i]);
      }
   }

bool XMSS_WOTS_Verification_Operation::is_valid_signature(const uint8_t sig[],
                                                          size_t sig_len)
   {
   const XMSS_WOTS_Parameters& w = m_pub_key.public_key().wots_parameters();

   BOTAN_ASSERT(sig_len == w.element_size() * w.len(),
                "Invalid signature size.");

   wots_keysig_t signature(0);
   signature.reserve(sig_len);

   size_t begin = 0;
   size_t end = 0;
   while(signature.size() < w.len())
      {
      begin = end;
      end = begin + w.element_size();
      signature.push_back(secure_vector<uint8_t>(sig + begin, sig + end));
      }

   XMSS_WOTS_PublicKey pubkey_msg(w.oid(),
                                  m_msg_buf,
                                  signature,
                                  m_pub_key.address(),
                                  m_pub_key.public_key().public_seed());

   return pubkey_msg.key_data() == m_pub_key.public_key().key_data();
   }

}

