/*
 * SPHINCS+ Address
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SPHINCS_PLUS_ADDRESS_H_
#define BOTAN_SPHINCS_PLUS_ADDRESS_H_

#include <array>

#include <botan/hash.h>
#include <botan/internal/loadstor.h>

namespace Botan {

enum class Sphincs_Address_Type : uint32_t
   {
      WotsHash = 0,
      WotsPublicKeyCompression = 1,
      HashTree = 2,
      ForsTree = 3,
      ForsTreeRootsCompression = 4,
      WotsKeyGeneration = 5,
      ForsKeyGeneration = 6
   };


class BOTAN_TEST_API Sphincs_Address
   {
   private:
      static constexpr size_t layer_offset = 0;
      static constexpr size_t tree_offset = 1; // 96bits
      static constexpr size_t type_offset = 4;
      static constexpr size_t keypair_offset = 5;
      static constexpr size_t chain_offset = 6;
      static constexpr size_t hash_offset = 7;
      static constexpr size_t tree_height_offset = chain_offset;
      static constexpr size_t tree_index_offset = hash_offset;

   public:
      using enum Sphincs_Address_Type;

      Sphincs_Address()
         {
         m_address.fill(0);
         }

      Sphincs_Address(std::array<uint32_t, 8> address)
         {
         std::copy(address.begin(), address.end(), m_address.begin());
         }

      Sphincs_Address& set_layer(uint32_t layer)
         {
         m_address[layer_offset] = layer;
         return *this;
         }

      Sphincs_Address& set_tree(uint64_t tree)
         {
         m_address[tree_offset + 0] = 0; // not required by all current instances
         m_address[tree_offset + 1] = static_cast<uint32_t>(tree >> 32);
         m_address[tree_offset + 2] = static_cast<uint32_t>(tree);
         return *this;
         }

      Sphincs_Address& set_type(Sphincs_Address_Type type)
         {
         m_address[type_offset] = static_cast<uint32_t>(type);
         return *this;
         }

      /* These functions are used for WOTS and FORS addresses. */

      Sphincs_Address& set_keypair(uint32_t keypair)
         {
         m_address[keypair_offset] = keypair;
         return *this;
         }

      Sphincs_Address& set_chain(uint32_t chain)
         {
         m_address[chain_offset] = chain;
         return *this;
         }

      Sphincs_Address& set_hash(uint32_t hash)
         {
         m_address[hash_offset] = hash;
         return *this;
         }

      /* These functions are used for all hash tree addresses (including FORS). */

      Sphincs_Address& set_tree_height(uint32_t tree_height)
         {
         m_address[tree_height_offset] = tree_height;
         return *this;
         }

      Sphincs_Address& set_tree_index(uint32_t tree_index)
         {
         m_address[tree_index_offset] = tree_index;
         return *this;
         }

      void copy_subtree_from(const Sphincs_Address& other)
         {
         m_address[0] = other.m_address[0];
         m_address[1] = other.m_address[1];
         m_address[2] = other.m_address[2];
         m_address[3] = other.m_address[3];
         }

      static Sphincs_Address as_subtree_from(const Sphincs_Address& other)
         {
         Sphincs_Address result;
         result.copy_subtree_from(other);
         return result;
         }

      void copy_keypair_from(const Sphincs_Address other)
         {
         m_address[0] = other.m_address[0];
         m_address[1] = other.m_address[1];
         m_address[2] = other.m_address[2];
         m_address[3] = other.m_address[3];
         m_address[5] = other.m_address[5];
         }

      static Sphincs_Address as_keypair_from(const Sphincs_Address& other)
         {
         Sphincs_Address result;
         result.copy_keypair_from(other);
         return result;
         }

      void apply_to_hash(HashFunction& hash) const
         {
         for(auto element : m_address)
            {
            hash.update_be(element);
            }
         }

      std::array<uint8_t, 32> to_bytes() const
         {
         std::array<uint8_t, 32> result;
         for(unsigned int i = 0; i < m_address.size(); ++i)
            {
            store_be(m_address[i], result.data() + (i * 4));
            }
         return result;
         }

   private:
      std::array<uint32_t, 8> m_address;
   };

}

#endif
