/*
 * XMSS^MT Signature
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSSMT_SIGNATURE_H_
#define BOTAN_XMSSMT_SIGNATURE_H_

#include <botan/exceptn.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <botan/xmssmt_parameters.h>
#include <botan/internal/xmss_core.h>
#include <botan/internal/xmss_wots.h>
#include <cstddef>

namespace Botan {

/**
 * Helper class for marshalling an XMSS^MT signature
 */
class XMSSMT_Signature final {
   public:
      /**
       * Creates a signature from an XMSS^MT signature method and a uint8_t sequence
       * representing a raw signature.
       *
       * @param oid XMSS^MT signature method
       * @param raw_sig An XMSS^MT signature serialized using
       *                XMSSMT_Signature::bytes().
       **/
      XMSSMT_Signature(XMSSMT_Parameters::xmssmt_algorithm_t oid, std::span<const uint8_t> raw_sig);

      /**
       * Creates an XMSS^MT Signature from XMSS^MT params, a leaf index used for signature
       * generation, a random value and a vector of reduced XMSS signatures.
       *
       * @param xmssmt_params XMSS^MT Parameters.
       * @param leaf_idx Leaf index used to generate the signature.
       * @param randomness A random value.
       * @param tree_sigs A vector of tree signatures.
       **/
      XMSSMT_Signature(XMSSMT_Parameters xmssmt_params,
                       uint64_t leaf_idx,
                       secure_vector<uint8_t> randomness,
                       std::vector<XMSS_TreeSignature> tree_sigs) :
            m_xmssmt_params(std::move(xmssmt_params)),
            m_leaf_idx(leaf_idx),
            m_randomness(std::move(randomness)),
            m_tree_sigs(std::move(tree_sigs)) {}

      uint64_t unused_leaf_index() const { return m_leaf_idx; }

      const secure_vector<uint8_t>& randomness() const { return m_randomness; }

      const std::vector<XMSS_TreeSignature>& trees() const { return m_tree_sigs; }

      const XMSS_TreeSignature& tree(size_t i) const { return m_tree_sigs[i]; }

      /**
       * Generates a serialized representation of XMSS^MT Signature by
       * concatenating the following elements in order:
       * ceil(h/8) leaf index, n-bytes randomness, d * (ots_signature + authentication path) reduced XMSS signatures
       *
       * n is the element_size(), len equal to len(), h the tree height, d the number of layers in the hypertree,
       * defined by the chosen XMSS^MT signature method.
       *
       * @return serialized signature, a sequence of
       *         (ceil(h / 8) + n + (h + d * len) * n) bytes.
       **/
      std::vector<uint8_t> bytes() const;

   private:
      XMSSMT_Parameters m_xmssmt_params;
      uint64_t m_leaf_idx;
      secure_vector<uint8_t> m_randomness;
      std::vector<XMSS_TreeSignature> m_tree_sigs;
};

}  // namespace Botan

#endif
