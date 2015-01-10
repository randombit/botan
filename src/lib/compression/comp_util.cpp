/*
* Allocation Tracker
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/comp_util.h>
#include <cstring>
#include <cstdlib>

namespace Botan {

void* Compression_Alloc_Info::do_malloc(size_t n, size_t size)
   {
   const size_t total_sz = n * size;

   void* ptr = std::malloc(total_sz);
   m_current_allocs[ptr] = total_sz;
   return ptr;
   }

void Compression_Alloc_Info::do_free(void* ptr)
   {
   if(ptr)
      {
      auto i = m_current_allocs.find(ptr);

      if(i == m_current_allocs.end())
         throw std::runtime_error("Compression_Alloc_Info::free got pointer not allocated by us");

      std::memset(ptr, 0, i->second);
      std::free(ptr);
      m_current_allocs.erase(i);
      }
   }

}
