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
#include <botan/internal/os_utils.h>
#include <algorithm>

namespace Botan {

Stateful_Key_Index_Registry& Stateful_Key_Index_Registry::global() {
   static Stateful_Key_Index_Registry g_registry;
   return g_registry;
}

Stateful_Key_Index_Registry::Stateful_Key_Index_Registry() : m_process_id(OS::get_process_id()) {}

Stateful_Key_Index_Registry::~Stateful_Key_Index_Registry() = default;

Stateful_Key_Index_Registry::KeyId::KeyId(std::string_view algo_name,
                                          std::span<const uint8_t> algo_params,
                                          uint64_t max_operations,
                                          std::span<const uint8_t> key_material_1,
                                          std::span<const uint8_t> key_material_2) :
      m_process_id(OS::get_process_id()), m_max_operations(max_operations) {
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
   if(this->fork_detected(key_id)) {
      throw Invalid_State("Stateful key index registry cannot be used after fork");
   }

   auto [i, inserted] = m_registry.emplace(key_id, 0);

   if(!inserted && i->first.max_operations() != key_id.max_operations()) {
      throw Internal_Error("Stateful key was already registered with a different maximum operation count");
   }

   return i;
}

/*
* Fork detection for the process-wide one-time signature counters.
*
* Reusing a stateful signature leaf index is catastrophic (signing two messages
* under the same index compromises the key), and after fork() both processes
* hold copy-on-write duplicates of the counters. The registry fails closed
* rather than risk index reuse.
*
* There are two PIDs stored, one in the registry and one in each KeyId, because
* there are two possible cases where reuse might occur after a fork:
*
* - If the registry was used before the fork, then its stored PID will
*   not match the current PID, in which case the latch closes.
*
* - KeyId's PID catches the rarer case where a key was created prior to the
*   fork, but not used. In that case the registry has not yet been created in
*   either process, and it would be possible to use the same key (with the same
*   starting-from-0 index) in both processes.
*
* Fork detection is a one way latch, and intentionally coarse. Once any fork is
* seen, the whole registry is disabled for the rest of this process, including
* for keys that were freshly loaded in the child. This could be loosened
* (allowing newly loaded keys to be used in the child process) but the
* combination of stateful signature schemes plus fork() is a hazardous scenario
* and seems best to prohibit it entirely.
*
* lookup() runs this on every access, so read-only queries (current_index,
* remaining_operations, and to_bytes which serializes the current index) also
* throw in a forked child rather than returning a possibly-unsafe value.
*/
bool Stateful_Key_Index_Registry::fork_detected(const KeyId& key_id) {
   if(m_fork_detected) {
      return true;
   }

   const uint32_t current_process_id = OS::get_process_id();

   /*
   We assume OS::get_process_id returns 0 only if processes are not a thing on
   this system, in which case there is also no fork syscall
   */
   if(current_process_id == 0) {
      return false;
   }

   /*
   * If either the registry PID or the KeyId PID do not match the current process,
   * assume a fork occurred and latch closed.
   */
   if((m_process_id != 0 && m_process_id != current_process_id) ||
      (key_id.m_process_id != 0 && key_id.m_process_id != current_process_id)) {
      m_fork_detected = true;
   }

   return m_fork_detected;
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
