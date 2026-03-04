/*
 * XMSS^MT Signature
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmssmt_signature.h>

#include <botan/xmssmt_parameters.h>
#include <botan/internal/loadstor.h>
#include <iterator>

namespace Botan {

XMSSMT_Signature::XMSSMT_Signature(XMSSMT_Parameters::xmssmt_algorithm_t oid, std::span<const uint8_t> raw_sig) :
      m_xmssmt_params(XMSSMT_Parameters(oid)), m_leaf_idx(0), m_randomness(0, 0x00) {
   const size_t idx_size = m_xmssmt_params.encoded_idx_size();

   // (ceil(h / 8) + n + (h + d * len) * n)
   if(raw_sig.size() !=
      (idx_size + (m_xmssmt_params.tree_height() + (m_xmssmt_params.tree_layers() * m_xmssmt_params.len()) + 1) *
                     m_xmssmt_params.element_size())) {
      throw Decoding_Error("XMSS^MT signature size invalid.");
   }

   for(size_t i = 0; i < idx_size; i++) {
      m_leaf_idx = ((m_leaf_idx << 8) | raw_sig[i]);
   }

   if(m_leaf_idx >= m_xmssmt_params.total_number_of_signatures()) {
      throw Decoding_Error("XMSS^MT signature leaf index out of bounds.");
   }

   auto begin = raw_sig.begin() + idx_size;
   auto end = begin + m_xmssmt_params.element_size();
   std::copy(begin, end, std::back_inserter(m_randomness));

   for(size_t d = 0; d < m_xmssmt_params.tree_layers(); d++) {
      XMSS_TreeSignature tmp_tree_sig;
      for(size_t i = 0; i < m_xmssmt_params.len(); i++) {
         begin = end;
         end = begin + m_xmssmt_params.element_size();
         tmp_tree_sig.ots_signature.push_back(secure_vector<uint8_t>(0));
         tmp_tree_sig.ots_signature.back().reserve(m_xmssmt_params.element_size());
         std::copy(begin, end, std::back_inserter(tmp_tree_sig.ots_signature.back()));
      }

      for(size_t i = 0; i < m_xmssmt_params.xmss_tree_height(); i++) {
         begin = end;
         end = begin + m_xmssmt_params.element_size();
         tmp_tree_sig.authentication_path.push_back(secure_vector<uint8_t>(0));
         tmp_tree_sig.authentication_path.back().reserve(m_xmssmt_params.element_size());
         std::copy(begin, end, std::back_inserter(tmp_tree_sig.authentication_path.back()));
      }
      m_tree_sigs.push_back(std::move(tmp_tree_sig));
   }
}

std::vector<uint8_t> XMSSMT_Signature::bytes() const {
   std::vector<uint8_t> result(m_xmssmt_params.encoded_idx_size());
   for(size_t i = 0; i < result.size(); i++) {
      result[result.size() - 1 - i] = static_cast<uint8_t>(m_leaf_idx >> (8 * i));
   }

   std::copy(m_randomness.begin(), m_randomness.end(), std::back_inserter(result));

   for(size_t d = 0; d < m_tree_sigs.size(); d++) {
      for(const auto& sig : tree(d).ots_signature) {
         std::copy(sig.begin(), sig.end(), std::back_inserter(result));
      }

      for(const auto& auth : tree(d).authentication_path) {
         std::copy(auth.begin(), auth.end(), std::back_inserter(result));
      }
   }
   return result;
}

}  // namespace Botan
