/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MEM_POOL_H_
#define BOTAN_MEM_POOL_H_

#include <botan/types.h>
#include <botan/mutex.h>
#include <vector>

namespace Botan {

class Memory_Pool final
   {
   public:
      /**
      * Initialize a memory pool. The memory is not owned by *this,
      * it must be freed by the caller.
      * @param pool the pool
      * @param pool_size size of pool
      * @param page_size some nominal page size (does not need to match
      *        the system page size)
      * @param min_allocation return null for allocs for smaller amounts
      * @param max_allocation return null for allocs of larger amounts
      * @param align_bit align all returned memory to (1<<align_bit) bytes
      */
      Memory_Pool(uint8_t* pool,
                  size_t pool_size,
                  size_t page_size,
                  size_t min_allocation,
                  size_t max_allocation,
                  uint8_t align_bit);

      void* allocate(size_t size);

      bool deallocate(void* p, size_t size) BOTAN_NOEXCEPT;

      Memory_Pool(const Memory_Pool&) = delete;

      Memory_Pool& operator=(const Memory_Pool&) = delete;

   private:
      const size_t m_page_size = 0;
      const size_t m_min_alloc = 0;
      const size_t m_max_alloc = 0;
      const uint8_t m_align_bit = 0;

      mutex_type m_mutex;

      std::vector<std::pair<size_t, size_t>> m_freelist;
      uint8_t* m_pool = nullptr;
      size_t m_pool_size = 0;
   };

}

#endif
