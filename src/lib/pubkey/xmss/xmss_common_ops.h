/*
 * XMSS Common Ops
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_COMMON_OPS_H_
#define BOTAN_XMSS_COMMON_OPS_H_

#include <botan/secmem.h>
#include <botan/xmss_parameters.h>
#include <botan/internal/xmss_address.h>
#include <span>
#include <vector>

namespace Botan {

class XMSS_Hash;

typedef std::vector<secure_vector<uint8_t>> wots_keysig_t;

/**
 * Bundles the WOTS+ signature and the authentication path of a single XMSS
 * tree. For XMSS this makes up the entire signature (together with the leaf
 * index and randomness), while an XMSS^MT signature contains one such
 * "reduced signature" per hypertree layer.
 **/
struct XMSS_TreeSignature final {
   public:
      wots_keysig_t ots_signature;
      wots_keysig_t authentication_path;
};

/**
 * Operations shared by XMSS signature generation and verification operations.
 **/
class XMSS_Common_Ops {
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
        * @param[in] element_size Size of each node in bytes, the parameter "n"
        **/
      static void randomize_tree_hash(secure_vector<uint8_t>& result,
                                      const secure_vector<uint8_t>& left,
                                      const secure_vector<uint8_t>& right,
                                      XMSS_Address adrs,
                                      const secure_vector<uint8_t>& seed,
                                      XMSS_Hash& hash,
                                      size_t element_size);

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
       * @param[in] element_size Size of each node in bytes, the parameter "n"
       * @param[in] wots_len Number of WOTS+ chains, the parameter "len"
      **/
      static void create_l_tree(secure_vector<uint8_t>& result,
                                const wots_keysig_t& pk,
                                XMSS_Address adrs,
                                const secure_vector<uint8_t>& seed,
                                XMSS_Hash& hash,
                                size_t element_size,
                                size_t wots_len);

      /**
       * Algorithm 8: "ltree", applied to many WOTS+ public keys at once,
       * batching the hash calls of each tree level across all keys.
       *
       * @param[out] leaves The compressed n-byte value of each key
       * @param[in,out] pks The WOTS+ public keys, each len*n bytes,
       *                contiguous. Destroyed by the computation.
       * @param[in,out] addrs Per key, its L-tree address with the L-tree
       *                address set. The tree height/index and key/mask
       *                mode are modified.
       * @param[in] seed The public seed
       * @param[in] hash Instance of XMSS_Hash, that may only be used by the
       *            thread executing create_l_trees.
       * @param[in] element_size Size of each node in bytes, the parameter "n"
       * @param[in] wots_len Number of WOTS+ chains, the parameter "len"
      **/
      static void create_l_trees(std::span<uint8_t> leaves,
                                 std::span<uint8_t> pks,
                                 std::span<XMSS_Address> addrs,
                                 std::span<const uint8_t> seed,
                                 XMSS_Hash& hash,
                                 size_t element_size,
                                 size_t wots_len);

      /**
       * Algorithm 13: "XMSS_rootFromSig"
       * Computes a root node using a tree signature and a message.
       *
       * @param[in] idx_leaf Index of the WOTS+ key pair (the leaf) within the
       *            tree.
       * @param[in] tree_sig The WOTS+ signature and authentication path.
       * @param[in] msg The signed message (for XMSS^MT layers above the
       *            lowest: the root node of the tree below).
       * @param[in] adrs Address of the tree. The caller presets the layer and
       *            tree address fields (both zero for XMSS).
       * @param[in] seed The public seed.
       * @param[in] hash The hash instance to use.
       * @param[in] wots_params The WOTS+ parameters.
       * @param[in] tree_height Height of the tree, the parameter "h"
       *            (for XMSS^MT: the height of a single layer's tree, "h/d").
       *
       * @return An n-byte string holding the value of the root of the tree
       *         defined by the input parameters.
       **/
      static secure_vector<uint8_t> root_from_signature(uint32_t idx_leaf,
                                                        const XMSS_TreeSignature& tree_sig,
                                                        const secure_vector<uint8_t>& msg,
                                                        XMSS_Address adrs,
                                                        const secure_vector<uint8_t>& seed,
                                                        XMSS_Hash& hash,
                                                        const XMSS_WOTS_Parameters& wots_params,
                                                        size_t tree_height);
};

}  // namespace Botan

#endif
