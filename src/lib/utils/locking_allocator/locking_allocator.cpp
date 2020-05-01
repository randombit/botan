/*
* Mlock Allocator
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/locking_allocator.h>
#include <botan/secmem.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/mem_pool.h>
#include <new>
#include <type_traits>

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
      m_locked_pages = OS::allocate_locked_pages(mem_to_lock / page_size);

      if(m_locked_pages.size() > 0)
         {
         m_pool.reset(new Memory_Pool(m_locked_pages, page_size));
         }
      }
   }

mlock_allocator::~mlock_allocator()
   {
   if(m_pool)
      {
      m_pool.reset();
      // OS::free_locked_pages scrubs the memory before free
      OS::free_locked_pages(m_locked_pages);
      }
   }

mlock_allocator& mlock_allocator::instance()
   {
   return mlock_allocator_instance;
   }

/*
Schwarz counter / nifty counter idiom
see: https://en.wikibooks.org/wiki/More_C%2B%2B_Idioms/Nifty_Counter
*/
static int nifty_counter;
static typename std::aligned_storage<sizeof (mlock_allocator), alignof (mlock_allocator)>::type
   mlock_allocator_buf;
mlock_allocator& mlock_allocator_instance = reinterpret_cast<mlock_allocator&> (mlock_allocator_buf);

mlock_allocator_initializer::mlock_allocator_initializer ()
   {
   if (nifty_counter++ == 0)
      {
      new (&mlock_allocator_instance) mlock_allocator(); // placement new
      }
   }

mlock_allocator_initializer::~mlock_allocator_initializer ()
   {
   if (--nifty_counter == 0)
      {
      (&mlock_allocator_instance)->~mlock_allocator(); // placement delete
      }
   }

}
