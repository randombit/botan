/*
* (C) 2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/allocator.h>

#include <botan/mem_ops.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/target_info.h>
#include <cstdlib>
#include <new>
#include <span>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   #include <botan/internal/locking_allocator.h>
#endif

namespace Botan {

BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size) {
   if(elems == 0 || elem_size == 0) {
      return nullptr;
   }

   // Some calloc implementations do not check for overflow (?!?)
   const auto bytes = checked_mul(elems, elem_size);
   if(!bytes.has_value()) {
      throw std::bad_alloc();
   }

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(const auto buf = mlock_allocator::instance().allocate(*bytes); !buf.empty()) {
      return buf.data();
   }
#endif

#if defined(BOTAN_TARGET_OS_HAS_ALLOC_CONCEAL)
   void* ptr = ::calloc_conceal(elems, elem_size);
#else
   // NOLINTNEXTLINE(*-const-correctness) bug in clang-tidy
   void* ptr = std::calloc(elems, elem_size);  // NOLINT(*-no-malloc,*-owning-memory)
#endif
   if(ptr == nullptr) {
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
   /*
   allocate_memory throws on overflow before reaching the pool, so if the
   size overflows here the pointer cannot have come from the pool.
   */
   if(const auto bytes = checked_mul(elems, elem_size)) {
      const std::span<uint8_t> buf(static_cast<uint8_t*>(p), *bytes);
      if(mlock_allocator::instance().deallocate(buf)) {
         return;
      }
   }
#endif

   std::free(p);  // NOLINT(*-no-malloc,*-owning-memory)
}

void initialize_allocator() {
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   mlock_allocator::instance();
#endif
}

}  // namespace Botan
