/*
 * XMSS Signature Operation
 * Signature generation operation for Extended Hash-Based Signatures (XMSS) as
 * defined in:
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 *
 * (C) 2016,2017,2018 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_signature_operation.h>
#include <botan/internal/xmss_tools.h>

namespace Botan {

XMSS_Signature_Operation::XMSS_Signature_Operation(
   const XMSS_PrivateKey& private_key) :
   m_priv_key(private_key),
   m_xmss_params(private_key.xmss_oid()),
   m_hash(private_key.xmss_hash_function()),
   m_randomness(0),
   m_leaf_idx(0),
   m_is_initialized(false)
   {}

XMSS_WOTS_PublicKey::TreeSignature
XMSS_Signature_Operation::generate_tree_signature(const secure_vector<uint8_t>& msg,
      XMSS_PrivateKey& xmss_priv_key,
      XMSS_Address& adrs)
   {

   wots_keysig_t auth_path = build_auth_path(xmss_priv_key, adrs);
   adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   adrs.set_ots_address(m_leaf_idx);

   wots_keysig_t sig_ots = xmss_priv_key.wots_private_key().sign(msg, adrs);
   return XMSS_WOTS_PublicKey::TreeSignature(sig_ots, auth_path);
   }

XMSS_Signature
XMSS_Signature_Operation::sign(const secure_vector<uint8_t>& msg_hash,
                               XMSS_PrivateKey& xmss_priv_key)
   {
   XMSS_Address adrs;
   XMSS_Signature sig(m_leaf_idx,
                      m_randomness,
                      generate_tree_signature(msg_hash, xmss_priv_key,adrs));
   return sig;
   }

size_t XMSS_Signature_Operation::signature_length() const
   {
   return sizeof(uint64_t) + // size of leaf index
          m_xmss_params.element_size() +
          m_xmss_params.len() * m_xmss_params.element_size() +
          m_xmss_params.tree_height() * m_xmss_params.element_size();
   }

wots_keysig_t
XMSS_Signature_Operation::build_auth_path(XMSS_PrivateKey& priv_key,
      XMSS_Address& adrs)
   {
   wots_keysig_t auth_path(m_xmss_params.tree_height());
   adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);

   for(size_t j = 0; j < m_xmss_params.tree_height(); j++)
      {
      size_t k = (m_leaf_idx / (1ULL << j)) ^ 0x01;
      auth_path[j] = priv_key.tree_hash(k * (1ULL << j), j, adrs);
      }

   return auth_path;
   }

void XMSS_Signature_Operation::update(const uint8_t msg[], size_t msg_len)
   {
   initialize();
   m_hash.h_msg_update(msg, msg_len);
   }

secure_vector<uint8_t>
XMSS_Signature_Operation::sign(RandomNumberGenerator&)
   {
   initialize();
   secure_vector<uint8_t> signature(sign(m_hash.h_msg_final(),
                                         m_priv_key).bytes());
   m_is_initialized = false;
   return signature;
   }

void XMSS_Signature_Operation::initialize()
   {
   // return if we already initialized and reserved a leaf index for signing.
   if(m_is_initialized)
      { return; }

   secure_vector<uint8_t> index_bytes;
   // reserve leaf index so it can not be reused in by another signature
   // operation using the same private key.
   m_leaf_idx = static_cast<uint32_t>(m_priv_key.reserve_unused_leaf_index());

   // write prefix for message hashing into buffer.
   XMSS_Tools::concat(index_bytes, m_leaf_idx, 32);
   m_randomness = m_hash.prf(m_priv_key.prf(), index_bytes);
   index_bytes.clear();
   XMSS_Tools::concat(index_bytes, m_leaf_idx,
                      m_priv_key.xmss_parameters().element_size());
   m_hash.h_msg_init(m_randomness,
                     m_priv_key.root(),
                     index_bytes);
   m_is_initialized = true;
   }

}

