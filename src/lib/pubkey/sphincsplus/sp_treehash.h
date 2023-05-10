/*
 * Sphincs+ treehash logic
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Parts of this file have been adapted from https://github.com/sphincs/sphincsplus
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SP_TREEHASH_H_
#define BOTAN_SP_TREEHASH_H_

#include <botan/sp_parameters.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_address.h>
#include <botan/internal/sp_types.h>


namespace Botan {

using GenerateLeafFunction =
   std::function<void(std::span<uint8_t> /* leaf out parameter */,
                      uint32_t /* address index */)>;

/**
 * Implements a generic Merkle tree hash
 */
BOTAN_TEST_API void treehash_spec(std::span<uint8_t> out_root,
                                  std::span<uint8_t> out_auth_path,
                                  const Sphincs_Parameters& params,
                                  Sphincs_Hash_Functions& hashes,
                                  const SphincsPublicSeed& pub_seed,
                                  uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
                                  GenerateLeafFunction gen_leaf,
                                  Sphincs_Address& tree_address);

}

#endif