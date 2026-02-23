/*
 * (C) 2016 Matthias Gierlings
 *     2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_STATEFUL_KEY_INDEX_REGISTRY_H_
#define BOTAN_STATEFUL_KEY_INDEX_REGISTRY_H_

#include <botan/mutex.h>
#include <botan/types.h>
#include <array>
#include <map>
#include <span>
#include <string_view>

namespace Botan {

/**
 * A process-wide registry mapping stateful key identity to a shared
 * atomic counter. Ensures that independent copies of the same key
 * material (e.g. deserialized separately) share a single leaf index,
 * preventing catastrophic one-time signature reuse.
 *
 * Used by XMSS and HSS-LMS.
 */
class Stateful_Key_Index_Registry final {
   public:
      class KeyId {
         public:
            /**
            * Create a KeyId for some kind of key material
            *
            * @param algo_name     Algorithm name (ex "XMSS", "HSS-LMS")
            * @param algo_params   Algorithm specific parameters
            * @param key_material_1 First part of key identifying material
            * @param key_material_2 Second part of key identifying material (can be omitted)
            */
            KeyId(std::string_view algo_name,
                  uint32_t algo_params,
                  std::span<const uint8_t> key_material_1,
                  std::span<const uint8_t> key_material_2);

            KeyId() = default;

            auto operator<=>(const KeyId& other) const = default;

         private:
            std::array<uint8_t, 32> m_val;
      };

      Stateful_Key_Index_Registry(const Stateful_Key_Index_Registry&) = delete;
      Stateful_Key_Index_Registry(Stateful_Key_Index_Registry&&) = delete;
      Stateful_Key_Index_Registry& operator=(const Stateful_Key_Index_Registry&) = delete;
      Stateful_Key_Index_Registry& operator=(Stateful_Key_Index_Registry&&) = delete;
      ~Stateful_Key_Index_Registry();

      /**
       * Retrieve the process-wide instance
       */
      static Stateful_Key_Index_Registry& global();

      /**
      * Return the current counter
      */
      uint64_t current_index(const KeyId& key_id);

      /**
      * Return a new counter
      */
      uint64_t reserve_next_index(const KeyId& key_id);

      /**
      * Set the counter to at least min (but if already higher it will retain its current value)
      */
      void set_index_lower_bound(const KeyId& key_id, uint64_t min);

      /**
      * If the current counter is >= max returns 0, otherwise max - counter
      */
      uint64_t remaining_operations(const KeyId& key_id, uint64_t max);

   private:
      typedef std::map<KeyId, uint64_t> RegistryMap;

      RegistryMap::iterator lookup(const KeyId& key_id);

      Stateful_Key_Index_Registry();

      mutex_type m_mutex;
      RegistryMap m_registry;
};

}  // namespace Botan

#endif
