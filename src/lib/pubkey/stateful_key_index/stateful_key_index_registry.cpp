/*
 * (C) 2016 Matthias Gierlings
 *     2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/stateful_key_index_registry.h>

#include <botan/assert.h>
#include <botan/hash.h>

namespace Botan {

Stateful_Key_Index_Registry& Stateful_Key_Index_Registry::global() {
   static Stateful_Key_Index_Registry g_registry;
   return g_registry;
}

Stateful_Key_Index_Registry::Stateful_Key_Index_Registry() = default;

Stateful_Key_Index_Registry::~Stateful_Key_Index_Registry() = default;

Stateful_Key_Index_Registry::KeyId::KeyId(std::string_view algo_name,
                                          uint32_t algo_params,
                                          std::span<const uint8_t> key_material_1,
                                          std::span<const uint8_t> key_material_2) :
      m_val() {
   auto hash = HashFunction::create_or_throw("SHA-256");

   hash->update("Botan Stateful_Key_Index_Registry KeyID");
   hash->update_be(static_cast<uint64_t>(algo_name.size()));
   hash->update(algo_name);
   hash->update_be(algo_params);
   hash->update_be(static_cast<uint64_t>(key_material_1.size()));
   hash->update(key_material_1);
   hash->update_be(static_cast<uint64_t>(key_material_2.size()));
   hash->update(key_material_2);

   BOTAN_ASSERT_NOMSG(hash->output_length() == m_val.size());

   hash->final(m_val);
}

// Lock must be held while this function is called
std::shared_ptr<std::atomic<uint64_t>> Stateful_Key_Index_Registry::lookup(const KeyId& key_id) {
   for(const auto& reg : m_registry) {
      if(reg.key_id == key_id) {
         return reg.leaf_index;
      }
   }

   m_registry.push_back({key_id, std::make_shared<std::atomic<uint64_t>>(0)});
   return m_registry.back().leaf_index;
}

uint64_t Stateful_Key_Index_Registry::current_index(const KeyId& key_id) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   auto idx = this->lookup(key_id);
   return (*idx);
}

uint64_t Stateful_Key_Index_Registry::reserve_next_index(const KeyId& key_id) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   auto idx = this->lookup(key_id);
   return idx->fetch_add(1);
}

void Stateful_Key_Index_Registry::set_index_lower_bound(const KeyId& key_id, uint64_t min) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   auto idx = this->lookup(key_id);

   uint64_t current = 0;

   // NOLINTNEXTLINE(*-avoid-do-while)
   do {
      current = idx->load();
      if(current > min) {
         return;
      }
   } while(!idx->compare_exchange_strong(current, min));
}

uint64_t Stateful_Key_Index_Registry::remaining_operations(const KeyId& key_id, uint64_t max) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   const uint64_t idx = this->lookup(key_id)->load();

   if(idx >= max) {
      return 0;
   } else {
      return max - idx;
   }
}

}  // namespace Botan
