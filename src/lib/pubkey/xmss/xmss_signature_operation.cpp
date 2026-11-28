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
 *     2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_signature_operation.h>

#include <botan/internal/xmss_tools.h>
#include <utility>

namespace Botan {

XMSS_Signature_Operation::XMSS_Signature_Operation(const XMSS_PrivateKey& private_key) :
      m_priv_key(private_key), m_hash(private_key.xmss_parameters()), m_verifier(private_key) {}

size_t XMSS_Signature_Operation::signature_length() const {
   const auto& params = m_priv_key.xmss_parameters();
   return sizeof(uint32_t) +  // size of leaf index
          params.element_size() + params.len() * params.element_size() + params.tree_height() * params.element_size();
}

void XMSS_Signature_Operation::update(std::span<const uint8_t> input) {
   // The leaf index is part of the message hash prefix, so the message is
   // buffered to avoid reserving a leaf before sign() is called
   m_msg_buffer.insert(m_msg_buffer.end(), input.begin(), input.end());
}

std::vector<uint8_t> XMSS_Signature_Operation::sign(RandomNumberGenerator& /*rng*/) {
   const std::vector<uint8_t> msg = std::exchange(m_msg_buffer, {});

   const auto& params = m_priv_key.xmss_parameters();
   const size_t n = params.element_size();

   // reserve leaf index so it can not be reused by another signature
   // operation using the same private key.
   std::vector<uint8_t> auth_path_bytes(params.tree_height() * n);
   const auto leaf_idx = static_cast<uint32_t>(m_priv_key.reserve_leaf(auth_path_bytes, m_hash));

   secure_vector<uint8_t> index_bytes;
   secure_vector<uint8_t> randomness;

   // write prefix for message hashing into buffer.
   xmss_concat(index_bytes, leaf_idx, 32);
   m_hash.prf(randomness, m_priv_key.prf_value(), index_bytes);
   index_bytes.clear();
   xmss_concat(index_bytes, leaf_idx, params.element_size());
   m_hash.h_msg_init(randomness, m_priv_key.root(), index_bytes);
   m_hash.h_msg_update(msg);

   const auto msg_hash = m_hash.h_msg_final();

   wots_keysig_t auth_path(params.tree_height());
   for(size_t j = 0; j < params.tree_height(); j++) {
      const auto node = std::span(auth_path_bytes).subspan(j * n, n);
      auth_path[j].assign(node.begin(), node.end());
   }

   XMSS_Address adrs;
   adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   adrs.set_ots_address(leaf_idx);

   XMSS_Signature::TreeSignature tree_sig;
   tree_sig.authentication_path = auth_path;
   tree_sig.ots_signature =
      m_priv_key.wots_private_key_for(adrs, m_hash).sign(msg_hash, m_priv_key.public_seed(), adrs, m_hash);

   const XMSS_Signature sig(leaf_idx, randomness, tree_sig);
   auto sig_bytes = sig.bytes();

   if(!m_verifier.is_valid_signature_of(msg, sig_bytes)) {
      // Discard the cache so the next signature is computed from the seed alone
      m_priv_key.discard_cached_tree();
      throw Internal_Error("XMSS signature failed verification");
   }

   return sig_bytes;
}

AlgorithmIdentifier XMSS_Signature_Operation::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string("XMSS"), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

}  // namespace Botan
