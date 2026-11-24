/*
* Mlock Allocator
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MLOCK_ALLOCATOR_H_
#define BOTAN_MLOCK_ALLOCATOR_H_

#include <botan/types.h>
#include <memory>
#include <span>
#include <vector>

namespace Botan {

class Memory_Pool;

class mlock_allocator final {
   public:
      static mlock_allocator& instance() noexcept;

      /**
      * Allocate bytes from the locked memory pool
      * @return the allocated bytes, or an empty span if the pool is
      *         unavailable or cannot serve the request
      */
      std::span<uint8_t> allocate(size_t bytes);

      /**
      * Return memory to the locked memory pool
      * @return true if buf was allocated from this pool and released
      */
      bool deallocate(std::span<uint8_t> buf) noexcept;

      mlock_allocator(const mlock_allocator&) = delete;
      mlock_allocator(mlock_allocator&&) = delete;
      mlock_allocator& operator=(const mlock_allocator&) = delete;
      mlock_allocator& operator=(mlock_allocator&&) = delete;

      mlock_allocator() noexcept;

      ~mlock_allocator();

   private:
      std::unique_ptr<Memory_Pool> m_pool;
      std::vector<std::span<uint8_t>> m_locked_pages;
};

}  // namespace Botan

#endif
