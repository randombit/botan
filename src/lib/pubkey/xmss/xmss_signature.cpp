/*
 * XMSS Signature
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_signature.h>
#include <cmath>

namespace Botan {

XMSS_Signature::XMSS_Signature(XMSS_Parameters::xmss_algorithm_t oid,
                               const secure_vector<uint8_t>& raw_sig)
   : m_leaf_idx(0), m_randomness(0, 0x00), m_tree_sig()
   {
   BOTAN_ASSERT(sizeof(size_t) >= std::ceil(static_cast<float>(
                   (XMSS_Parameters(oid)).tree_height()) / 8.f),
                   "System type \"size_t\" not big enough to support"
                   " leaf index.");

   XMSS_Parameters xmss_params(oid);
   uint64_t leaf_idx = 0;
   for(size_t i = 0; i < 8; i++)
      leaf_idx = ((leaf_idx << 8) | raw_sig[i]);

   if(leaf_idx >= (1ull << (xmss_params.tree_height() - 1)))
      {
      throw Integrity_Failure("XMSS signature leaf index out of "
                              "bounds.");
      }
   m_leaf_idx = static_cast<size_t>(leaf_idx);

   auto begin = raw_sig.begin() + sizeof(uint64_t);
   auto end = begin + xmss_params.element_size();
   std::copy(begin, end, std::back_inserter(m_randomness));

   for(size_t i = 0; i < xmss_params.len(); i++)
      {
      begin = end;
      end = begin + xmss_params.element_size();
      m_tree_sig.ots_signature().push_back(secure_vector<uint8_t>(0));
      m_tree_sig.ots_signature().back().reserve(
         xmss_params.element_size());
      std::copy(begin,
                end,
                std::back_inserter(m_tree_sig.ots_signature().back()));
      }

   for(size_t i = 0; i < xmss_params.tree_height(); i++)
      {
      begin = end;
      end = begin + xmss_params.element_size();
      m_tree_sig.authentication_path().push_back(secure_vector<uint8_t>(0));
      m_tree_sig.authentication_path().back().reserve(
         xmss_params.element_size());
      std::copy(begin,
                end,
                std::back_inserter(m_tree_sig.authentication_path().back()));
      }
   }

secure_vector<uint8_t> XMSS_Signature::bytes() const
   {
   secure_vector<uint8_t> result
      {
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 56U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 48U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 40U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 32U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 24U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 16U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >>  8U),
      static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx)       )
      };

   std::copy(m_randomness.begin(),
             m_randomness.end(),
             std::back_inserter(result));

   for(const auto& sig : tree().ots_signature())
      {
      std::copy(sig.begin(),
                sig.end(),
                std::back_inserter(result));
      }

   for(const auto& auth : tree().authentication_path())
      {
      std::copy(auth.begin(),
                auth.end(),
                std::back_inserter(result));
      }
   return result;
   }

}
