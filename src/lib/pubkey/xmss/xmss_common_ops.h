/*
 * XMSS Common Ops
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_COMMON_OPS_H__
#define BOTAN_XMSS_COMMON_OPS_H__

#include <vector>
#include <botan/secmem.h>
#include <botan/assert.h>
#include <botan/xmss_parameters.h>
#include <botan/xmss_address.h>
#include <botan/xmss_hash.h>

namespace Botan {

typedef std::vector<secure_vector<uint8_t>> wots_keysig_t;

/**
 * Operations shared by XMSS signature generation and verification operations.
 **/
class XMSS_Common_Ops {
public:
  XMSS_Common_Ops(XMSS_Parameters::xmss_algorithm_t oid)
    : m_xmss_params(oid), m_hash(m_xmss_params.hash_function_name()) {};

protected:
  /**
    * Algorithm 7: "RAND_HASH"
    *
    * Generates a randomized hash.
    *
    * @param[out] result The resulting randomized hash.
    * @param[in] left Left half of the hash function input.
    * @param[in] right Right half of the hash function input.
    * @param[in] adrs Adress of the hash function call.
    * @param[in] seed The seed for G.
    **/
  void randomize_tree_hash(
    secure_vector<uint8_t>& result,
    const secure_vector<uint8_t>& left,
    const secure_vector<uint8_t>& right,
    XMSS_Address& adrs,
    const secure_vector<uint8_t>& seed);

  /**
   * Algorithm 8: "ltree"
   * Create an L-tree used to compute the leaves of the binary hash tree.
   * Takes a WOTS+ public key and compresses it to a single n-byte value.
   *
   * @param[out] result Public key compressed to a single n-byte value
   *             pk[0].
   * @param[in] pk Winternitz One Time Signatures+ public key.
   * @param[in] adrs Address encoding the address of the L-Tree
   * @param[in] seed The seed generated during the public key generation.
   **/
  void create_l_tree(
    secure_vector<uint8_t>& result,
    wots_keysig_t pk,
    XMSS_Address& adrs,
    const secure_vector<uint8_t>& seed);

protected:
  XMSS_Parameters m_xmss_params;
  XMSS_Hash m_hash;

};

}

#endif
