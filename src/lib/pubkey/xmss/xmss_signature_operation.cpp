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

XMSS_Signature_Operation::XMSS_Signature_Operation(const XMSS_PrivateKey& private_key) :
      m_priv_key(private_key),
      m_hash(private_key.xmss_parameters()),
      m_randomness(0),
      m_leaf_idx(0),
      m_is_initialized(false) {}

XMSS_Signature::TreeSignature XMSS_Signature_Operation::generate_tree_signature(const secure_vector<uint8_t>& msg,
                                                                                XMSS_PrivateKey& xmss_priv_key,
                                                                                XMSS_Address& adrs) {
   XMSS_Signature::TreeSignature result;

   result.authentication_path = build_auth_path(xmss_priv_key, adrs);
   adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   adrs.set_ots_address(m_leaf_idx);

   result.ots_signature =
      xmss_priv_key.wots_private_key_for(adrs, m_hash).sign(msg, xmss_priv_key.public_seed(), adrs, m_hash);

   return result;
}

XMSS_Signature XMSS_Signature_Operation::sign(const secure_vector<uint8_t>& msg_hash, XMSS_PrivateKey& xmss_priv_key) {
   XMSS_Address adrs;
   XMSS_Signature sig(m_leaf_idx, m_randomness, generate_tree_signature(msg_hash, xmss_priv_key, adrs));
   return sig;
}

size_t XMSS_Signature_Operation::signature_length() const {
   const auto& params = m_priv_key.xmss_parameters();
   return sizeof(uint64_t) +  // size of leaf index
          params.element_size() + params.len() * params.element_size() + params.tree_height() * params.element_size();
}

wots_keysig_t XMSS_Signature_Operation::build_auth_path(XMSS_PrivateKey& priv_key, XMSS_Address& adrs) {
   const auto& params = m_priv_key.xmss_parameters();
   wots_keysig_t auth_path(params.tree_height());
   adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);

   for(size_t j = 0; j < params.tree_height(); j++) {
      size_t k = (m_leaf_idx / (static_cast<size_t>(1) << j)) ^ 0x01;
      auth_path[j] = priv_key.tree_hash(k * (static_cast<size_t>(1) << j), j, adrs);
   }

   return auth_path;
}

void XMSS_Signature_Operation::update(std::span<const uint8_t> input) {
   initialize();
   m_hash.h_msg_update(input);
}

std::vector<uint8_t> XMSS_Signature_Operation::sign(RandomNumberGenerator& /*rng*/) {
   initialize();
   auto sig = sign(m_hash.h_msg_final(), m_priv_key).bytes();
   m_is_initialized = false;
   return sig;
}

void XMSS_Signature_Operation::initialize() {
   // return if we already initialized and reserved a leaf index for signing.
   if(m_is_initialized) {
      return;
   }

   secure_vector<uint8_t> index_bytes;
   // reserve leaf index so it can not be reused by another signature
   // operation using the same private key.
   m_leaf_idx = static_cast<uint32_t>(m_priv_key.reserve_unused_leaf_index());

   // write prefix for message hashing into buffer.
   XMSS_Tools::concat(index_bytes, m_leaf_idx, 32);
   m_hash.prf(m_randomness, m_priv_key.prf_value(), index_bytes);
   index_bytes.clear();
   XMSS_Tools::concat(index_bytes, m_leaf_idx, m_priv_key.xmss_parameters().element_size());
   m_hash.h_msg_init(m_randomness, m_priv_key.root(), index_bytes);
   m_is_initialized = true;
}

AlgorithmIdentifier XMSS_Signature_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("XMSS"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

}  // namespace Botan
