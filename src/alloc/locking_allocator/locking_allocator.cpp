/*
* Mlock Allocator
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/locking_allocator.h>
#include <botan/internal/assert.h>
#include <cstring>
#include <sys/mman.h>
#include <sys/resource.h>

namespace Botan {

namespace {

size_t mlock_limit()
   {
   struct rlimit limits;
   ::getrlimit(RLIMIT_MEMLOCK, &limits);

   if(limits.rlim_cur < limits.rlim_max)
      {
      limits.rlim_cur = limits.rlim_max;
      ::setrlimit(RLIMIT_MEMLOCK, &limits);
      ::getrlimit(RLIMIT_MEMLOCK, &limits);
      }

   return std::min<size_t>(limits.rlim_cur, 256*1024);
   }

}

void* mlock_allocator::allocate(size_t n, size_t alignment)
   {
   if(!m_pool || n >= m_poolsize)
      return nullptr; // bigger than the whole pool!

   std::lock_guard<std::mutex> lock(m_mutex);

   std::pair<size_t, size_t> best_fit(0, 0);

   for(auto i = m_freelist.begin(); i != m_freelist.end(); ++i)
      {
      if((i->first % alignment) != 0)
         continue;

      if(i->second == n)
         {
         m_freelist.erase(i);
         return m_pool + i->first;
         }
      else if((i->second > n) &&
              ((best_fit.second > i->second) || (best_fit.second == 0)))
         {
         best_fit = *i;
         }
      }

   if(best_fit.second >= n)
      {
      const size_t offset = best_fit.first;
      const size_t left = best_fit.second - n;

      BOTAN_ASSERT(m_freelist.erase(offset) == 1,
                   "Bad manipulation in freelist");

      m_freelist[offset+n] = left;

      return m_pool + offset;
      }

   return nullptr;
   }

bool mlock_allocator::deallocate(void* p, size_t n)
   {
   if(!m_pool || p < m_pool || p >= static_cast<byte*>(m_pool) + m_poolsize)
      return false;

   std::lock_guard<std::mutex> lock(m_mutex);

   size_t start = static_cast<byte*>(p) - m_pool;

   m_freelist[start] = n;

   std::map<size_t, size_t> new_freelist;
   std::pair<size_t, size_t> current(0, 0);

   for(auto i : m_freelist)
      {
      if(current.second == 0)
         {
         current = i;
         }
      else if(i.first == current.first + current.second)
         {
         current.second += i.second;
         }
      else
         {
         new_freelist.insert(current);
         current = i;
         }
      }

   if(current.second != 0)
       new_freelist.insert(current);

   std::swap(m_freelist, new_freelist);

   return true;
   }

mlock_allocator::mlock_allocator() :
   m_poolsize(mlock_limit()),
   m_pool(nullptr)
   {
#if !defined(MAP_NOCORE)
   #define MAP_NOCORE 0
#endif

   if(m_poolsize)
      {
      m_pool = static_cast<byte*>(
         ::mmap(
            nullptr, m_poolsize,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
            -1, 0));

      if(m_pool == static_cast<void*>(MAP_FAILED))
         throw std::runtime_error("Failed to mmap pool");

      std::memset(m_pool, 0x00, m_poolsize);

      if(::mlock(m_pool, m_poolsize) != 0)
         {
         ::munmap(m_pool, m_poolsize);
         m_pool = nullptr;
         throw std::runtime_error("Failed to lock pool");
         }

      m_freelist[0] = m_poolsize;
      }
   }

mlock_allocator::~mlock_allocator()
   {
   if(m_pool)
      {
      std::memset(m_pool, 0, m_poolsize);
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
