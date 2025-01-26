/*
* Mlock Allocator
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/locking_allocator.h>

#include <botan/compiler.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/mem_pool.h>
#include <botan/internal/os_utils.h>

namespace Botan {

void* mlock_allocator::allocate(size_t num_elems, size_t elem_size) {
   if(!m_pool) {
      return nullptr;
   }

   if(auto n = checked_mul(num_elems, elem_size)) {
      return m_pool->allocate(n.value());
   } else {
      // overflow!
      return nullptr;
   }
}

bool mlock_allocator::deallocate(void* p, size_t num_elems, size_t elem_size) noexcept {
   if(!m_pool) {
      return false;
   }

   if(auto n = checked_mul(num_elems, elem_size)) {
      return m_pool->deallocate(p, n.value());
   } else {
      /*
      We return nullptr in allocate if there was an overflow, so if an
      overflow occurs here we know the pointer was not allocated by this pool.
      */
      return false;
   }
}

mlock_allocator::mlock_allocator() {
   const size_t mem_to_lock = OS::get_memory_locking_limit();
   const size_t page_size = OS::system_page_size();

   if(mem_to_lock > 0 && mem_to_lock % page_size == 0) {
      m_locked_pages = OS::allocate_locked_pages(mem_to_lock / page_size);

      if(!m_locked_pages.empty()) {
         m_pool = std::make_unique<Memory_Pool>(m_locked_pages, page_size);
      }
   }
}

mlock_allocator::~mlock_allocator() {
   if(m_pool) {
      m_pool.reset();
      // OS::free_locked_pages scrubs the memory before free
      OS::free_locked_pages(m_locked_pages);
   }
}

namespace {

// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
BOTAN_EARLY_INIT(101) mlock_allocator g_mlock_allocator;

}  // namespace

mlock_allocator& mlock_allocator::instance() {
   return g_mlock_allocator;
}

}  // namespace Botan
