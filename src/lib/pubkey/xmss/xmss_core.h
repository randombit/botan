/*
 * XMSS Core Operations
 * (C) 2016,2017 Matthias Gierlings
 * (C) 2019 Jack Lloyd
 * (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_CORE_H_
#define BOTAN_XMSS_CORE_H_

#include <botan/secmem.h>
#include <botan/xmss_parameters.h>
#include <botan/internal/xmss_address.h>
#include <botan/internal/xmss_wots.h>
#include <functional>
#include <vector>

namespace Botan {

class XMSS_Hash;

typedef std::vector<secure_vector<uint8_t>> wots_keysig_t;

struct XMSS_TreeSignature final {
   public:
      wots_keysig_t ots_signature;
      wots_keysig_t authentication_path;
};

/**
 * Some core algorithms of XMSS that are shared across operations and with XMSS^MT
 **/
class XMSS_Core_Ops {
   public:
      /**
        * Algorithm 7: "RAND_HASH"
        *
        * Generates a randomized hash.
        *
        * This overload is used in multithreaded scenarios, where it is
        * required to provide separate instances of XMSS_Hash to each
        * thread.
        *
        * @param[out] result The resulting randomized hash.
        * @param[in] left Left half of the hash function input.
        * @param[in] right Right half of the hash function input.
        * @param[in] adrs Address of the hash function call.
        * @param[in] seed The seed for G.
        * @param[in] hash Instance of XMSS_Hash, that may only by the thread
        *            executing generate_public_key.
        * @param[in] xmss_element_size Size of a node in XMSS.
        **/
      static void randomize_tree_hash(secure_vector<uint8_t>& result,
                                      const secure_vector<uint8_t>& left,
                                      const secure_vector<uint8_t>& right,
                                      XMSS_Address adrs,
                                      const secure_vector<uint8_t>& seed,
                                      XMSS_Hash& hash,
                                      size_t xmss_element_size);

      /**
       * Algorithm 8: "ltree"
       * Create an L-tree used to compute the leaves of the binary hash tree.
       * Takes a WOTS+ public key and compresses it to a single n-byte value.
       *
       * This overload is used in multithreaded scenarios, where it is
       * required to provide separate instances of XMSS_Hash to each thread.
       *
       * @param[out] result Public key compressed to a single n-byte value
       *             pk[0].
       * @param[in] pk Winternitz One Time Signatures+ public key.
       * @param[in] adrs Address encoding the address of the L-Tree
       * @param[in] seed The seed generated during the public key generation.
       * @param[in] hash Instance of XMSS_Hash, that may only be used by the
       *            thread executing create_l_tree.
       * @param[in] xmss_element_size Size of a node in XMSS.
       * @param[in] xmss_wots_len WOTS+ len value.
      **/
      static void create_l_tree(secure_vector<uint8_t>& result,
                                wots_keysig_t pk,
                                XMSS_Address adrs,
                                const secure_vector<uint8_t>& seed,
                                XMSS_Hash& hash,
                                size_t xmss_element_size,
                                size_t xmss_wots_len);

      /**
       * Algorithm 13: "XMSS_rootFromSig"
       * Computes a root node using a (reduced) XMSS signature, a message and a seed.
       *
       * @param[in] idx_leaf Index of the leaf node.
       * @param[in] tree_sig A reduced XMSS signature.
       * @param[in] msg A message (or intermediate root node for XMSS^MT).
       * @param[in] adrs A XMSS tree address.
       * @param[in] seed The public seed.
       * @param[in] hash a XMSS_Hash instance.
       * @param[in] xmss_element_size Size of a node in XMSS.
       * @param[in] xmss_tree_height The XMSS tree height (height of one subtree for XMSS^MT).
       * @param[in] xmss_wots_len WOTS+ len value.
       * @param[in] ots_oid The OID for the used OTS algorithm.
       *
       * @return An n-byte string holding the value of the root of a tree
       *         defined by the input parameters.
       **/
      static secure_vector<uint8_t> root_from_signature(uint32_t idx_leaf,
                                                        const XMSS_TreeSignature& tree_sig,
                                                        const secure_vector<uint8_t>& msg,
                                                        XMSS_Address adrs,
                                                        const secure_vector<uint8_t>& seed,
                                                        XMSS_Hash& hash,
                                                        size_t xmss_element_size,
                                                        size_t xmss_tree_height,
                                                        size_t xmss_wots_len,
                                                        XMSS_WOTS_Parameters::ots_algorithm_t ots_oid);

      /**
         * Algorithm 9: "treeHash"
         * Computes the internal n-byte nodes of a Merkle tree.
         *
         * @param start_idx The start index.
         * @param target_node_height Height of the target node.
         * @param adrs Address of the tree containing the target node.
         * @param hash Instance of XMSS_Hash, that may only by the thread
         *            executing generate_public_key.
         * @param wots_params WOTS+ parameters.
         * @param public_seed The public seed.
         * @param wots_public_key_for_fn function pointer to the private-key wots_public_key_for() method
         *
         * @return The root node of a tree of height target_node height with the
         *         leftmost leaf being the hash of the WOTS+ pk with index
         *         start_idx.
         **/
      static secure_vector<uint8_t> tree_hash(
         uint32_t start_idx,
         size_t target_node_height,
         XMSS_Address adrs,
         XMSS_Hash& hash,
         const XMSS_WOTS_Parameters& wots_params,
         const secure_vector<uint8_t>& public_seed,
         const std::function<XMSS_WOTS_PublicKey(XMSS_Address adrs, XMSS_Hash& hash)>& wots_public_key_for_fn);

      /**
         * Helper for multithreaded tree hashing.
         */
      static XMSS_Address tree_hash_subtree(
         secure_vector<uint8_t>& result,
         uint32_t start_idx,
         size_t target_node_height,
         XMSS_Address adrs,
         XMSS_Hash& hash,
         const XMSS_WOTS_Parameters& wots_params,
         const secure_vector<uint8_t>& public_seed,
         const std::function<XMSS_WOTS_PublicKey(XMSS_Address adrs, XMSS_Hash& hash)>& wots_public_key_for);
};

}  // namespace Botan

#endif
