/*
 * XMSS Index Registry
 * A registry for XMSS private keys, keeps track of the leaf index for
 * independent copies of the same key.
 * (C) 2016 Matthias Gierlings
 *     2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_index_registry.h>

#include <botan/assert.h>
#include <botan/hash.h>

namespace Botan {

namespace {

std::array<uint8_t, 32> make_xmss_index_key_id(uint32_t params,
                                               std::span<const uint8_t> private_seed,
                                               std::span<const uint8_t> prf) {
   const std::string_view index_hash_function = "SHA-256";
   std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(index_hash_function);
   hash->update("Botan XMSS Index Registry KeyId");
   hash->update_be(params);
   hash->update(private_seed);
   hash->update(prf);

   std::array<uint8_t, 32> key_id{};
   hash->final(key_id);
   return key_id;
}

}  // namespace

//static
XMSS_Index_Registry& XMSS_Index_Registry::get_instance() {
   static XMSS_Index_Registry g_xmss_index_registry;
   return g_xmss_index_registry;
}

XMSS_Index_Registry::XMSS_Index_Registry() = default;

XMSS_Index_Registry::~XMSS_Index_Registry() = default;

std::shared_ptr<Atomic<size_t>> XMSS_Index_Registry::get(uint32_t params,
                                                         std::span<const uint8_t> private_seed,
                                                         std::span<const uint8_t> prf) {
   // Compute the key id outside the lock
   const auto id = make_xmss_index_key_id(params, private_seed, prf);

   const lock_guard_type<mutex_type> lock(m_mutex);

   for(const auto& reg : m_registry) {
      if(reg.key_id == id) {
         return reg.leaf_index;
      }
   }

   m_registry.push_back({id, std::make_shared<Atomic<size_t>>(0)});
   return m_registry.back().leaf_index;
}

}  // namespace Botan
