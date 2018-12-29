/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/internal/mem_pool.h>
#include <botan/internal/bit_ops.h>
#include <vector>
#include <map>
#include <utility>

namespace {

size_t compute_expected_alignment(size_t plen)
   {
   if(Botan::is_power_of_2(plen))
      {
      return plen;
      }
   else
      {
      return 8;
      }
   }

}

void fuzz(const uint8_t in[], size_t in_len)
   {
   const size_t page_size = 4096;
   const size_t pages = 4;

   static std::vector<uint8_t> raw_mem(page_size * pages);

   Botan::Memory_Pool pool(raw_mem.data(), pages, page_size);
   std::map<uint8_t*, size_t> ptrs;

   while(in_len > 0)
      {
      const uint8_t op = in[0] % 2;
      size_t idx = (in[0] >> 1);
      in += 1;
      in_len -= 1;

      if(in_len > 0 && idx < 4)
         {
         idx = idx * 256 + in[0];
         in += 1;
         in_len -= 1;
         }

      //printf("%d %d\n", op, idx);

      if(op == 0)
         {
         const size_t plen = idx + 1; // ensure non-zero
         uint8_t* p = static_cast<uint8_t*>(pool.allocate(plen));

         if(p)
            {
            const size_t expected_alignment = compute_expected_alignment(plen);
            if(reinterpret_cast<uintptr_t>(p) % expected_alignment != 0)
               {
               FUZZER_WRITE_AND_CRASH("Pointer allocated non-aligned pointer " << p);
               }

            //printf("alloc %d -> %p\n", plen, p);

            for(size_t i = 0; i != plen; ++i)
               {
               if(p[i] != 0)
                  {
                  FUZZER_WRITE_AND_CRASH("Pool gave out non-zeroed memory");
                  }
               }

            // verify it becomes zeroed later
            std::memset(p, idx, plen);

            auto insert = ptrs.insert(std::make_pair(p, plen));
            if(insert.second == false)
               {
               FUZZER_WRITE_AND_CRASH("Pointer " << p << " already existed\n");
               }

            auto itr = insert.first;

            // Verify this pointer doesn't overlap with the one before it
            if(itr != ptrs.begin())
               {
               auto before = std::prev(itr);
               auto ptr_before = *before;

               if(ptr_before.first + ptr_before.second > p)
                  {
                  FUZZER_WRITE_AND_CRASH("Previous " << ptr_before.first << "/" << ptr_before.second <<
                                         " overlaps with new " << p);
                  }
               }

            auto after = std::next(itr);

            if(after != ptrs.end())
               {
               if(p + plen > after->first)
                  {
                  FUZZER_WRITE_AND_CRASH("New " << p << "/" << plen << " overlaps following " << after->first);
                  }
               }
            }
         }
      else if(op == 1)
         {
         if(ptrs.empty())
            return;

         size_t which_ptr = idx % ptrs.size();

         auto itr = ptrs.begin();

         while(which_ptr-- > 0)
            {
            ++itr;
            }

         //printf("free %p %d\n", itr->first, itr->second);
         FUZZER_ASSERT_TRUE(pool.deallocate(itr->first, itr->second));
         ptrs.erase(itr);
         }
      }
   }
