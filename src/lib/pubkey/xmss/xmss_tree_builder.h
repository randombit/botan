/*
 * XMSS Tree Builder
 * (C) 2016,2017,2018 Matthias Gierlings
 * (C) 2019,2026 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_TREE_BUILDER_H_
#define BOTAN_XMSS_TREE_BUILDER_H_

#include <botan/secmem.h>
#include <botan/xmss.h>
#include <botan/internal/xmss_address.h>
#include <botan/internal/xmss_wots.h>
#include <span>

namespace Botan {

class XMSS_Hash;

/**
 * Bundles the inputs needed to compute the internal nodes (and root) of an
 * XMSS Merkle tree: the WOTS+ parameters and the public/private seeds. The
 * same computation is needed both during key generation (before the immutable
 * public key exists) and during signing (auth path computation), so it is
 * factored out here and shared via thin wrappers on XMSS_PrivateKey. It is
 * also used by XMSS^MT, which builds one XMSS tree per hypertree node; the
 * caller then presets the layer/tree fields of the passed XMSS_Address.
 **/
class XMSS_Tree_Builder final {
   public:
      XMSS_Tree_Builder(const XMSS_WOTS_Parameters& wots_params,
                        WOTS_Derivation_Method wots_derivation_method,
                        const secure_vector<uint8_t>& public_seed,
                        const secure_vector<uint8_t>& private_seed) :
            m_wots_params(wots_params),
            m_wots_derivation_method(wots_derivation_method),
            m_public_seed(public_seed),
            m_private_seed(private_seed) {}

      secure_vector<uint8_t> tree_hash(size_t start_idx,
                                       size_t target_node_height,
                                       const XMSS_Address& adrs,
                                       XMSS_Hash& hash) const;

      XMSS_WOTS_PrivateKey wots_private_key_for(const XMSS_Address& adrs, XMSS_Hash& hash) const;

      const secure_vector<uint8_t>& public_seed() const { return m_public_seed; }

   private:
      /**
      * Compute the leaves [start_idx, start_idx + count) of the tree into
      * leaves (count * n bytes)
      */
      void compute_leaves(
         std::span<uint8_t> leaves, size_t start_idx, size_t count, const XMSS_Address& adrs, XMSS_Hash& hash) const;

      /**
      * Derive the WOTS+ private keys of addrs.size() / len leaves into
      * sks; addrs holds the OTS hash address of every chain of every leaf
      */
      void wots_private_keys(std::span<uint8_t> sks, std::span<const XMSS_Address> addrs, XMSS_Hash& hash) const;

      XMSS_WOTS_Parameters m_wots_params;
      WOTS_Derivation_Method m_wots_derivation_method;
      const secure_vector<uint8_t>& m_public_seed;
      const secure_vector<uint8_t>& m_private_seed;
};

}  // namespace Botan

#endif
