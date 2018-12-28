/*
* Mlock Allocator
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/locking_allocator.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/mem_pool.h>

namespace Botan {

void* mlock_allocator::allocate(size_t num_elems, size_t elem_size)
   {
   if(!m_pool)
      return nullptr;

   const size_t n = num_elems * elem_size;
   if(n / elem_size != num_elems)
      return nullptr; // overflow!

   return m_pool->allocate(n);
   }

bool mlock_allocator::deallocate(void* p, size_t num_elems, size_t elem_size) noexcept
   {
   if(!m_pool)
      return false;

   size_t n = num_elems * elem_size;

   /*
   We return nullptr in allocate if there was an overflow, so if an
   overflow occurs here we know the pointer was not allocated by this pool.
   */
   if(n / elem_size != num_elems)
      return false;

   return m_pool->deallocate(p, n);
   }

mlock_allocator::mlock_allocator()
   {
   const size_t mem_to_lock = OS::get_memory_locking_limit();
   const size_t page_size = OS::system_page_size();

   if(mem_to_lock > 0 && mem_to_lock % page_size == 0)
      {
      m_locked_pages = static_cast<uint8_t*>(OS::allocate_locked_pages(mem_to_lock));

      if(m_locked_pages)
         {
         m_locked_pages_size = mem_to_lock;

         m_pool.reset(new Memory_Pool(m_locked_pages,
                                      m_locked_pages_size / page_size,
                                      page_size));
         }
      }
   }

mlock_allocator::~mlock_allocator()
   {
   if(m_pool)
      {
      m_pool.reset();
      // OS::free_locked_pages scrubs the memory before free
      OS::free_locked_pages(m_locked_pages, m_locked_pages_size);
      }
   }

mlock_allocator& mlock_allocator::instance()
   {
   static mlock_allocator mlock;
   return mlock;
   }

}
