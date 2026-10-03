/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/x509_cert_cache.h>

#include <botan/hash.h>
#include <iterator>

namespace Botan {

X509_Certificate_Cache::X509_Certificate_Cache(size_t max_entries) : m_max_entries(max_entries) {}

X509_Certificate X509_Certificate_Cache::find_or_insert(std::span<const uint8_t> encoding) {
   if(m_max_entries == 0) {
      return X509_Certificate(encoding);
   }

   // Hash the DER
   auto sha256 = HashFunction::create_or_throw("SHA-256");
   DER_Hash hash;
   sha256->update(encoding);
   sha256->final(hash.m_hash);

   // Check for a cache hit
   {
      const lock_guard_type<mutex_type> lock(m_mutex);
      if(const auto it = m_cache.find(hash); it != m_cache.end()) {
         return it->second;
      }
   }

   // Deserialize the certificate
   X509_Certificate cert(encoding);

   // Lock again
   const lock_guard_type<mutex_type> lock(m_mutex);

   // Check for a cache hit (possibly racing with another thread)
   if(const auto it = m_cache.find(hash); it != m_cache.end()) {
      return it->second;
   }

   // Evict if required
   //
   // Drop a pseudo-random entry, chosen by the hash of the new one. Erasing
   // begin() is not a random drop: the standard library implementations
   // insert a node whose bucket was empty at the front of the list, so that
   // would often evict the entry inserted immediately before, and two
   // certificates that are looked up alternately could evict each other on
   // every lookup.
   //
   // Might make sense to add LRU here
   if(m_cache.size() >= m_max_entries) {
      auto victim = m_cache.begin();
      std::advance(victim, hash.hash() % m_cache.size());
      m_cache.erase(victim);
   }

   // Add the newly deserialized cert to the cache
   const auto it = m_cache.emplace(hash, std::move(cert)).first;
   return it->second;
}

}  // namespace Botan
