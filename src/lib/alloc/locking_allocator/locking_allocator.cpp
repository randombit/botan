/*
* Mlock Allocator
* (C) 2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/locking_allocator.h>
#include <botan/mem_ops.h>
#include <algorithm>
#include <string>

#include <sys/mman.h>
#include <sys/resource.h>

namespace Botan {

namespace {

/**
* Requests for objects of sizeof(T) will be aligned at
* sizeof(T)*ALIGNMENT_MULTIPLE bytes.
*/
const size_t ALIGNMENT_MULTIPLE = 2;

size_t mlock_limit()
   {
   /*
   * Linux defaults to only 64 KiB of mlockable memory per process
   * (too small) but BSDs offer a small fraction of total RAM (more
   * than we need). Bound the total mlock size to 512 KiB which is
   * enough to run the entire test suite without spilling to non-mlock
   * memory (and thus presumably also enough for many useful
   * programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   const size_t MLOCK_UPPER_BOUND = 512*1024;

   struct rlimit limits;
   ::getrlimit(RLIMIT_MEMLOCK, &limits);

   if(limits.rlim_cur < limits.rlim_max)
      {
      limits.rlim_cur = limits.rlim_max;
      ::setrlimit(RLIMIT_MEMLOCK, &limits);
      ::getrlimit(RLIMIT_MEMLOCK, &limits);
      }

   return std::min<size_t>(limits.rlim_cur, MLOCK_UPPER_BOUND);
   }

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
   const size_t alignment = ALIGNMENT_MULTIPLE * elem_size;

   if(n / elem_size != num_elems)
      return nullptr; // overflow!

   if(n > m_poolsize || n > BOTAN_MLOCK_ALLOCATOR_MAX_ALLOCATION)
      return nullptr;

   std::lock_guard<std::mutex> lock(m_mutex);

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

   std::lock_guard<std::mutex> lock(m_mutex);

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

mlock_allocator::mlock_allocator() :
   m_poolsize(mlock_limit()),
   m_pool(nullptr)
   {
#if !defined(MAP_NOCORE)
   #define MAP_NOCORE 0
#endif

#if !defined(MAP_ANONYMOUS)
   #define MAP_ANONYMOUS MAP_ANON
#endif

   if(m_poolsize)
      {
      m_pool = static_cast<byte*>(
         ::mmap(
            nullptr, m_poolsize,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
            -1, 0));

      if(m_pool == static_cast<byte*>(MAP_FAILED))
         {
         m_pool = nullptr;
         throw std::runtime_error("Failed to mmap locking_allocator pool");
         }

      clear_mem(m_pool, m_poolsize);

      if(::mlock(m_pool, m_poolsize) != 0)
         {
         ::munmap(m_pool, m_poolsize);
         m_pool = nullptr;
         throw std::runtime_error("Could not mlock " + std::to_string(m_poolsize) + " bytes");
         }

#if defined(MADV_DONTDUMP)
      ::madvise(m_pool, m_poolsize, MADV_DONTDUMP);
#endif

      m_freelist.push_back(std::make_pair(0, m_poolsize));
      }
   }

mlock_allocator::~mlock_allocator()
   {
   if(m_pool)
      {
      clear_mem(m_pool, m_poolsize);
      ::munlock(m_pool, m_poolsize);
      ::munmap(m_pool, m_poolsize);
      m_pool = nullptr;
      }
   }

mlock_allocator& mlock_allocator::instance()
   {
   static mlock_allocator mlock;
   return mlock;
   }

}
