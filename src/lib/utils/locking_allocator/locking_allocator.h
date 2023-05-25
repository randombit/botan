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
#include <vector>

namespace Botan {

class Memory_Pool;

class mlock_allocator final {
   public:
      static mlock_allocator& instance();

      void* allocate(size_t num_elems, size_t elem_size);

      bool deallocate(void* p, size_t num_elems, size_t elem_size) noexcept;

      mlock_allocator(const mlock_allocator&) = delete;

      mlock_allocator& operator=(const mlock_allocator&) = delete;

      mlock_allocator();

      ~mlock_allocator();

   private:
      std::unique_ptr<Memory_Pool> m_pool;
      std::vector<void*> m_locked_pages;
};

}  // namespace Botan

#endif
