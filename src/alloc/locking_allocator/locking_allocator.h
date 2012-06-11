/*
* Mlock Allocator
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MLOCK_ALLOCATOR_H__
#define BOTAN_MLOCK_ALLOCATOR_H__

#include <botan/types.h>
#include <vector>
#include <mutex>

namespace Botan {

class BOTAN_DLL mlock_allocator
   {
   public:
      static mlock_allocator& instance();

      void* allocate(size_t num_elems, size_t elem_size);

      bool deallocate(void* p, size_t num_elems, size_t elem_size);

   private:
      mlock_allocator();

      ~mlock_allocator();

      std::mutex m_mutex;
      size_t m_poolsize;
      std::vector<std::pair<size_t, size_t>> m_freelist;
      byte* m_pool;
   };

}

#endif
