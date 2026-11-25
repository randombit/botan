/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MEM_POOL_H_
#define BOTAN_MEM_POOL_H_

#include <botan/mutex.h>
#include <botan/types.h>
#include <deque>
#include <limits>
#include <map>
#include <span>
#include <vector>

namespace Botan {

class Bucket;

class BOTAN_TEST_API Memory_Pool final {
   public:
      /**
      * Initialize a memory pool. The memory is not owned by *this,
      * it must be freed by the caller.
      * @param pages a list of pages to allocate from
      * @param page_size the system page size, each page should
      *        point to exactly this much memory.
      */
      Memory_Pool(const std::vector<std::span<uint8_t>>& pages, size_t page_size);

      ~Memory_Pool() noexcept;

      /**
      * Allocate size bytes from the pool
      * @return the allocated (zeroed) bytes, or an empty span if the
      *         request cannot be served from the pool
      */
      std::span<uint8_t> allocate(size_t size);

      /**
      * Return memory to the pool
      * @param buf a span previously returned by allocate
      * @return true if buf belonged to this pool and was released
      */
      bool deallocate(std::span<uint8_t> buf) noexcept;

      Memory_Pool(const Memory_Pool&) = delete;
      Memory_Pool(Memory_Pool&&) = delete;

      Memory_Pool& operator=(const Memory_Pool&) = delete;
      Memory_Pool& operator=(Memory_Pool&&) = delete;

   private:
      const size_t m_page_size = 0;

      mutex_type m_mutex;

      std::vector<std::span<uint8_t>> m_free_pages;
      std::map<size_t, std::deque<Bucket>> m_buckets_for;
      uintptr_t m_min_page_ptr = std::numeric_limits<uintptr_t>::max();
      uintptr_t m_max_page_ptr = 0;
};

}  // namespace Botan

#endif
