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
#include <optional>
#include <span>
#include <string_view>

namespace Botan {

/**
 * A process-wide registry mapping stateful key identity to a shared
 * monotonic counter. Ensures that independent copies of the same key
 * material (e.g. deserialized separately) share a single leaf index,
 * preventing catastrophic one-time signature reuse.
 *
 * The same key material used with different algorithm parameters is
 * tracked independently, since the parameters are part of the key
 * identity. The maximum operation count is a function of the identity.
 *
 * Used by XMSS and HSS-LMS.
 *
 * If this registry or a key identity is inherited across fork(), it fails
 * closed and refuses to issue further indices in the child process.
 */
class Stateful_Key_Index_Registry final {
   public:
      class KeyId final {
         public:
            /**
            * Create a KeyId for some kind of key material
            *
            * @param algo_name     Algorithm name (ex "XMSS", "HSS-LMS")
            * @param algo_params   Encoding of the algorithm parameters
            * @param max_operations Maximum number of operations the key supports.
            *                       This must be derived from algo_params; equal
            *                       identities must have equal maximums.
            * @param key_material_1 First part of key identifying material
            * @param key_material_2 Second part of key identifying material (can be omitted)
            */
            KeyId(std::string_view algo_name,
                  std::span<const uint8_t> algo_params,
                  uint64_t max_operations,
                  std::span<const uint8_t> key_material_1,
                  std::span<const uint8_t> key_material_2);

            // A default constructed KeyId permits no operations
            KeyId() = default;

            uint64_t max_operations() const { return m_max_operations; }

            // Identity is the hash; the maximum is not hashed in, since an
            // inconsistent maximum forking the counter would be worse than
            // the error the registry raises for it.
            auto operator<=>(const KeyId& other) const { return m_val <=> other.m_val; }

            bool operator==(const KeyId& other) const { return m_val == other.m_val; }

         private:
            std::array<uint8_t, 32> m_val{};
            uint32_t m_process_id = 0;
            uint64_t m_max_operations = 0;

            friend class Stateful_Key_Index_Registry;
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
      * Reserve and return the next counter value, or nullopt if the counter
      * has already reached the key's maximum. The counter never increments
      * past the maximum, so it cannot wrap, and an exhausted key remains
      * exhausted.
      */
      std::optional<uint64_t> reserve_next_index(const KeyId& key_id);

      /**
      * Set the counter to at least min (but if already higher it will retain its current value)
      */
      void set_index_lower_bound(const KeyId& key_id, uint64_t min);

      /**
      * If the current counter is >= the key's maximum returns 0, otherwise maximum - counter
      */
      uint64_t remaining_operations(const KeyId& key_id);

   private:
      typedef std::map<KeyId, uint64_t> RegistryMap;

      RegistryMap::iterator lookup(const KeyId& key_id);
      bool fork_detected(const KeyId& key_id);

      Stateful_Key_Index_Registry();

      mutex_type m_mutex;
      RegistryMap m_registry;
      uint32_t m_process_id = 0;
      bool m_fork_detected = false;
};

}  // namespace Botan

#endif
