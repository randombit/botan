/*
* (C) 2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/allocator.h>

#include <botan/mem_ops.h>
#include <botan/internal/int_utils.h>
#include <cstdlib>
#include <new>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   #include <botan/internal/locking_allocator.h>
#endif

namespace Botan {

BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size) {
   if(elems == 0 || elem_size == 0) {
      return nullptr;
   }

   // Some calloc implementations do not check for overflow (?!?)
   if(!checked_mul(elems, elem_size).has_value()) {
      throw std::bad_alloc();
   }

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(void* p = mlock_allocator::instance().allocate(elems, elem_size)) {
      return p;
   }
#endif

#if defined(BOTAN_TARGET_OS_HAS_ALLOC_CONCEAL)
   void* ptr = ::calloc_conceal(elems, elem_size);
#else
   void* ptr = std::calloc(elems, elem_size);  // NOLINT(*-no-malloc)
#endif
   if(!ptr) {
      [[unlikely]] throw std::bad_alloc();
   }
   return ptr;
}

void deallocate_memory(void* p, size_t elems, size_t elem_size) {
   if(p == nullptr) {
      [[unlikely]] return;
   }

   secure_scrub_memory(p, elems * elem_size);

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(mlock_allocator::instance().deallocate(p, elems, elem_size)) {
      return;
   }
#endif

   std::free(p);  // NOLINT(*-no-malloc)
}

void initialize_allocator() {
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   mlock_allocator::instance();
#endif
}

}  // namespace Botan
