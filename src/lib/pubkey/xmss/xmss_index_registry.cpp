/*
 * XMSS Index Registry
 * A registry for XMSS private keys, keeps track of the leaf index for
 * independend copies of the same key.
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_index_registry.h>

#include <botan/hash.h>
#include <limits>

namespace Botan {

const std::string XMSS_Index_Registry::m_index_hash_function = "SHA-256";

//static
uint64_t XMSS_Index_Registry::make_key_id(const secure_vector<uint8_t>& private_seed,
                                          const secure_vector<uint8_t>& prf) {
   std::unique_ptr<HashFunction> hash = HashFunction::create(m_index_hash_function);
   BOTAN_ASSERT(hash != nullptr, "XMSS_Index_Registry requires SHA-256");
   hash->update(private_seed);
   hash->update(prf);
   secure_vector<uint8_t> result = hash->final();
   uint64_t key_id = 0;
   for(size_t i = 0; i < sizeof(key_id); i++) {
      key_id = ((key_id << 8) | result[i]);
   }

   return key_id;
}

std::shared_ptr<Atomic<size_t>> XMSS_Index_Registry::get(const secure_vector<uint8_t>& private_seed,
                                                         const secure_vector<uint8_t>& prf) {
   size_t pos = get(make_key_id(private_seed, prf));

   if(pos < std::numeric_limits<size_t>::max()) {
      return m_leaf_indices[pos];
   } else {
      return m_leaf_indices[add(make_key_id(private_seed, prf))];
   }
}

size_t XMSS_Index_Registry::get(uint64_t id) const {
   for(size_t i = 0; i < m_key_ids.size(); i++) {
      if(m_key_ids[i] == id) {
         return i;
      }
   }

   return std::numeric_limits<size_t>::max();
}

size_t XMSS_Index_Registry::add(uint64_t id, size_t last_unused) {
   lock_guard_type<mutex_type> lock(m_mutex);
   size_t pos = get(id);
   if(pos < m_key_ids.size()) {
      if(last_unused > *(m_leaf_indices[pos])) {
         m_leaf_indices[pos] = std::make_shared<Atomic<size_t>>(last_unused);
      }
      return pos;
   }

   m_key_ids.push_back(id);
   m_leaf_indices.push_back(std::make_shared<Atomic<size_t>>(last_unused));
   return m_key_ids.size() - 1;
}

}  // namespace Botan
