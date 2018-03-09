/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mem_pool.h>
#include <botan/mem_ops.h>
#include <botan/exceptn.h>
#include <algorithm>
#include <cstdlib>
#include <string>

namespace Botan {

namespace {

inline bool ptr_in_pool(const void* pool_ptr, size_t poolsize,
                        const void* buf_ptr, size_t bufsize)
   {
   const uintptr_t pool = reinterpret_cast<uintptr_t>(pool_ptr);
   const uintptr_t buf = reinterpret_cast<uintptr_t>(buf_ptr);
   return (buf >= pool) && (buf + bufsize <= pool + poolsize);
   }

inline size_t padding_for_alignment(size_t n, size_t alignment)
   {
   const size_t mod = n % alignment;
   if(mod == 0)
      return 0;
   return alignment - mod;
   }

}

Memory_Pool::Memory_Pool(uint8_t* pool,
                         size_t pool_size,
                         size_t page_size,
                         size_t min_alloc,
                         size_t max_alloc,
                         uint8_t align_bit) :
   m_page_size(page_size),
   m_min_alloc(min_alloc),
   m_max_alloc(max_alloc),
   m_align_bit(align_bit)
   {
   if(pool == nullptr)
      throw Invalid_Argument("Memory_Pool pool was null");

   if(m_min_alloc > m_max_alloc)
      throw Invalid_Argument("Memory_Pool min_alloc > max_alloc");

   if(m_align_bit > 6)
      throw Invalid_Argument("Memory_Pool invalid align_bit");

   // This is basically just to verify that the range is valid
   clear_mem(pool, pool_size);

   m_pool = pool;
   m_pool_size = pool_size;
   m_freelist.push_back(std::make_pair(0, m_pool_size));
   }

void* Memory_Pool::allocate(size_t req)
   {
   const size_t alignment = (1 << m_align_bit);

   if(req > m_pool_size)
      return nullptr;
   if(req < m_min_alloc || req > m_max_alloc)
      return nullptr;

   lock_guard_type<mutex_type> lock(m_mutex);

   auto best_fit = m_freelist.end();

   for(auto i = m_freelist.begin(); i != m_freelist.end(); ++i)
      {
      // If we have a perfect fit, use it immediately
      if(i->second == req && (i->first % alignment) == 0)
         {
         const size_t offset = i->first;
         m_freelist.erase(i);
         clear_mem(m_pool + offset, req);

         BOTAN_ASSERT((reinterpret_cast<uintptr_t>(m_pool) + offset) % alignment == 0,
                      "Returning correctly aligned pointer");

         return m_pool + offset;
         }


      if(((best_fit == m_freelist.end()) || (best_fit->second > i->second)) &&
         (i->second >= (req + padding_for_alignment(i->first, alignment))))
         {
         best_fit = i;
         }
      }

   if(best_fit != m_freelist.end())
      {
      const size_t offset = best_fit->first;

      const size_t alignment_padding = padding_for_alignment(offset, alignment);

      best_fit->first += req + alignment_padding;
      best_fit->second -= req + alignment_padding;

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

      clear_mem(m_pool + offset + alignment_padding, req);

      BOTAN_ASSERT((reinterpret_cast<uintptr_t>(m_pool) + offset + alignment_padding) % alignment == 0,
                   "Returning correctly aligned pointer");

      return m_pool + offset + alignment_padding;
      }

   return nullptr;
   }

bool Memory_Pool::deallocate(void* p, size_t n) BOTAN_NOEXCEPT
   {
   if(!ptr_in_pool(m_pool, m_pool_size, p, n))
      return false;

   std::memset(p, 0, n);

   lock_guard_type<mutex_type> lock(m_mutex);

   const size_t start = static_cast<uint8_t*>(p) - m_pool;

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

}
