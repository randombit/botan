/*
 * (C) 2016 Matthias Gierlings
 *     2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/stateful_key_index_registry.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <algorithm>

namespace Botan {

Stateful_Key_Index_Registry& Stateful_Key_Index_Registry::global() {
   static Stateful_Key_Index_Registry g_registry;
   return g_registry;
}

Stateful_Key_Index_Registry::Stateful_Key_Index_Registry() = default;

Stateful_Key_Index_Registry::~Stateful_Key_Index_Registry() = default;

Stateful_Key_Index_Registry::KeyId::KeyId(std::string_view algo_name,
                                          std::span<const uint8_t> algo_params,
                                          uint64_t max_operations,
                                          std::span<const uint8_t> key_material_1,
                                          std::span<const uint8_t> key_material_2) :
      m_max_operations(max_operations) {
   auto hash = HashFunction::create_or_throw("SHA-256");

   hash->update("Botan Stateful_Key_Index_Registry KeyID");
   hash->update_be(static_cast<uint64_t>(algo_name.size()));
   hash->update(algo_name);
   hash->update_be(static_cast<uint64_t>(algo_params.size()));
   hash->update(algo_params);
   hash->update_be(static_cast<uint64_t>(key_material_1.size()));
   hash->update(key_material_1);
   hash->update_be(static_cast<uint64_t>(key_material_2.size()));
   hash->update(key_material_2);

   BOTAN_ASSERT_NOMSG(hash->output_length() == m_val.size());

   hash->final(m_val);
}

// Lock must be held while this function is called
Stateful_Key_Index_Registry::RegistryMap::iterator Stateful_Key_Index_Registry::lookup(const KeyId& key_id) {
   auto [i, inserted] = m_registry.emplace(key_id, 0);

   if(!inserted && i->first.max_operations() != key_id.max_operations()) {
      throw Internal_Error("Stateful key was already registered with a different maximum operation count");
   }

   return i;
}

uint64_t Stateful_Key_Index_Registry::current_index(const KeyId& key_id) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   auto idx = this->lookup(key_id);
   return idx->second;
}

std::optional<uint64_t> Stateful_Key_Index_Registry::reserve_next_index(const KeyId& key_id) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   auto idx = this->lookup(key_id);
   const uint64_t cur = idx->second;
   if(cur >= key_id.max_operations()) {
      return std::nullopt;
   }
   idx->second = cur + 1;
   return cur;
}

void Stateful_Key_Index_Registry::set_index_lower_bound(const KeyId& key_id, uint64_t min) {
   BOTAN_ARG_CHECK(min <= key_id.max_operations(), "Index lower bound exceeds maximum operation count");
   const lock_guard_type<mutex_type> lock(m_mutex);
   auto idx = this->lookup(key_id);
   idx->second = std::max(idx->second, min);
}

uint64_t Stateful_Key_Index_Registry::remaining_operations(const KeyId& key_id) {
   const lock_guard_type<mutex_type> lock(m_mutex);
   const uint64_t idx = this->lookup(key_id)->second;
   const uint64_t max = key_id.max_operations();

   if(idx >= max) {
      return 0;
   } else {
      return max - idx;
   }
}

}  // namespace Botan
