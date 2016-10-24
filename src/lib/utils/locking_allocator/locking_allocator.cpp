/*
* Mlock Allocator
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/locking_allocator.h>
#include <botan/internal/os_utils.h>
#include <botan/mem_ops.h>
#include <algorithm>
#include <cstdlib>
#include <string>
#include <botan/mutex.h>

namespace Botan {

namespace {

bool ptr_in_pool(const void* pool_ptr, size_t poolsize,
                 const void* buf_ptr, size_t bufsize)
   {
   const uintptr_t pool = reinterpret_cast<uintptr_t>(pool_ptr);
   const uintptr_t buf = reinterpret_cast<uintptr_t>(buf_ptr);

   if(buf < pool || buf >= pool + poolsize)
      return false;

   BOTAN_ASSERT(buf + bufsize <= pool + poolsize,
                "Pointer does not partially overlap pool");

   return true;
   }

size_t padding_for_alignment(size_t offset, size_t desired_alignment)
   {
   size_t mod = offset % desired_alignment;
   if(mod == 0)
      return 0; // already right on
   return desired_alignment - mod;
   }

}

void* mlock_allocator::allocate(size_t num_elems, size_t elem_size)
   {
   if(!m_pool)
      return nullptr;

   const size_t n = num_elems * elem_size;
   const size_t alignment = 16;

   if(n / elem_size != num_elems)
      return nullptr; // overflow!

   if(n > m_poolsize)
      return nullptr;
   if(n < BOTAN_MLOCK_ALLOCATOR_MIN_ALLOCATION || n > BOTAN_MLOCK_ALLOCATOR_MAX_ALLOCATION)
      return nullptr;

   lock_guard_type<mutex_type> lock(m_mutex);

   auto best_fit = m_freelist.end();

   for(auto i = m_freelist.begin(); i != m_freelist.end(); ++i)
      {
      // If we have a perfect fit, use it immediately
      if(i->second == n && (i->first % alignment) == 0)
         {
         const size_t offset = i->first;
         m_freelist.erase(i);
         clear_mem(m_pool + offset, n);

         BOTAN_ASSERT((reinterpret_cast<size_t>(m_pool) + offset) % alignment == 0,
                      "Returning correctly aligned pointer");

         return m_pool + offset;
         }

      if((i->second >= (n + padding_for_alignment(i->first, alignment)) &&
          ((best_fit == m_freelist.end()) || (best_fit->second > i->second))))
         {
         best_fit = i;
         }
      }

   if(best_fit != m_freelist.end())
      {
      const size_t offset = best_fit->first;

      const size_t alignment_padding = padding_for_alignment(offset, alignment);

      best_fit->first += n + alignment_padding;
      best_fit->second -= n + alignment_padding;

      // Need to realign, split the block
      if(alignment_padding)
         {
         /*
         If we used the entire block except for small piece used for
         alignment at the beginning, so just update the entry already
         in place (as it is in the correct location), rather than
         deleting the empty range and inserting the new one in the
         same location.
         */
         if(best_fit->second == 0)
            {
            best_fit->first = offset;
            best_fit->second = alignment_padding;
            }
         else
            m_freelist.insert(best_fit, std::make_pair(offset, alignment_padding));
         }

      clear_mem(m_pool + offset + alignment_padding, n);

      BOTAN_ASSERT((reinterpret_cast<size_t>(m_pool) + offset + alignment_padding) % alignment == 0,
                   "Returning correctly aligned pointer");

      return m_pool + offset + alignment_padding;
      }

   return nullptr;
   }

bool mlock_allocator::deallocate(void* p, size_t num_elems, size_t elem_size)
   {
   if(!m_pool)
      return false;

   /*
   We do not have to zero the memory here, as
   secure_allocator::deallocate does that for all arguments before
   invoking the deallocator (us or delete[])
   */

   size_t n = num_elems * elem_size;

   /*
   We return nullptr in allocate if there was an overflow, so we
   should never ever see an overflow in a deallocation.
   */
   BOTAN_ASSERT(n / elem_size == num_elems,
                "No overflow in deallocation");

   if(!ptr_in_pool(m_pool, m_poolsize, p, n))
      return false;

   lock_guard_type<mutex_type> lock(m_mutex);

   const size_t start = static_cast<byte*>(p) - m_pool;

   auto comp = [](std::pair<size_t, size_t> x, std::pair<size_t, size_t> y){ return x.first < y.first; };

   auto i = std::lower_bound(m_freelist.begin(), m_freelist.end(),
                             std::make_pair(start, 0), comp);

   // try to merge with later block
   if(i != m_freelist.end() && start + n == i->first)
      {
      i->first = start;
      i->second += n;
      n = 0;
      }

   // try to merge with previous block
   if(i != m_freelist.begin())
      {
      auto prev = std::prev(i);

      if(prev->first + prev->second == start)
         {
         if(n)
            {
            prev->second += n;
            n = 0;
            }
         else
            {
            // merge adjoining
            prev->second += i->second;
            m_freelist.erase(i);
            }
         }
      }

   if(n != 0) // no merge possible?
      m_freelist.insert(i, std::make_pair(start, n));

   return true;
   }

mlock_allocator::mlock_allocator()
   {
   const size_t mem_to_lock = OS::get_memory_locking_limit();

   /*
   TODO: split into multiple single page allocations to
   help ASLR and guard pages to help reduce the damage of
   a wild reads or write by the application.
   */

   if(mem_to_lock)
      {
      m_pool = static_cast<byte*>(OS::allocate_locked_pages(mem_to_lock));

      if(m_pool != nullptr)
         {
         m_poolsize = mem_to_lock;
         m_freelist.push_back(std::make_pair(0, m_poolsize));
         }
      }
   }

mlock_allocator::~mlock_allocator()
   {
   if(m_pool)
      {
      zero_mem(m_pool, m_poolsize);
      OS::free_locked_pages(m_pool, m_poolsize);
      m_pool = nullptr;
      }
   }

mlock_allocator& mlock_allocator::instance()
   {
   static mlock_allocator mlock;
   return mlock;
   }

}
