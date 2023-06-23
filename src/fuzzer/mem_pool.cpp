/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/internal/bit_ops.h>
#include <botan/internal/mem_pool.h>
#include <map>
#include <utility>
#include <vector>

#include <cstdlib>

namespace {

size_t compute_expected_alignment(size_t plen) {
   if(Botan::is_power_of_2(plen)) {
      return plen;
   } else {
      return 8;
   }
}

struct RawPage {
   public:
      RawPage(void* p) : m_p(p) {}

      ~RawPage() {
         // NOLINTNEXTLINE(*-no-malloc)
         std::free(m_p);
      }

      RawPage(const RawPage& other) = default;
      RawPage& operator=(const RawPage& other) = default;

      RawPage(RawPage&& other) noexcept : m_p(nullptr) { std::swap(m_p, other.m_p); }

      RawPage& operator=(RawPage&& other) noexcept {
         if(this != &other) {
            std::swap(m_p, other.m_p);
         }
         return (*this);
      }

      void* ptr() const { return m_p; }

   private:
      void* m_p;
};

std::vector<RawPage> allocate_raw_pages(size_t count, size_t page_size) {
   std::vector<RawPage> pages;
   pages.reserve(count);

   for(size_t i = 0; i != count; ++i) {
      void* ptr = nullptr;

      int rc = ::posix_memalign(&ptr, page_size, page_size);
      FUZZER_ASSERT_EQUAL(rc, 0);

      if(ptr) {
         pages.push_back(RawPage(ptr));
      }
   }

   return pages;
}

}  // namespace

void fuzz(const uint8_t in[], size_t in_len) {
   const size_t page_count = 4;
   const size_t page_size = 4096;

   // static to avoid repeated allocations
   static std::vector<RawPage> raw_mem = allocate_raw_pages(page_count, page_size);

   std::vector<void*> mem_pages;
   mem_pages.reserve(raw_mem.size());
   for(size_t i = 0; i != raw_mem.size(); ++i) {
      mem_pages.push_back(raw_mem[i].ptr());
   }

   Botan::Memory_Pool pool(mem_pages, page_size);
   std::map<uint8_t*, size_t> ptrs;

   while(in_len > 0) {
      const uint8_t op = in[0] % 2;
      size_t idx = (in[0] >> 1);
      in += 1;
      in_len -= 1;

      if(in_len > 0 && idx < 4) {
         idx = idx * 256 + in[0];
         in += 1;
         in_len -= 1;
      }

      if(op == 0) {
         const size_t plen = idx + 1;  // ensure non-zero
         uint8_t* p = static_cast<uint8_t*>(pool.allocate(plen));

         if(p) {
            const size_t expected_alignment = compute_expected_alignment(plen);
            const size_t alignment = reinterpret_cast<uintptr_t>(p) % expected_alignment;
            if(alignment != 0) {
               FUZZER_WRITE_AND_CRASH("Pointer allocated non-aligned pointer "
                                      << static_cast<void*>(p) << " for len " << plen << " expected "
                                      << expected_alignment << " got " << alignment);
            }

            //printf("alloc %d -> %p\n", plen, p);

            for(size_t i = 0; i != plen; ++i) {
               if(p[i] != 0) {
                  FUZZER_WRITE_AND_CRASH("Pool gave out non-zeroed memory");
               }
            }

            // verify it becomes zeroed later
            std::memset(p, static_cast<int>(idx), plen);

            auto insert = ptrs.insert(std::make_pair(p, plen));
            if(insert.second == false) {
               FUZZER_WRITE_AND_CRASH("Pointer " << static_cast<void*>(p) << " already existed\n");
            }

            auto itr = insert.first;

            // Verify this pointer doesn't overlap with the one before it
            if(itr != ptrs.begin()) {
               auto before = std::prev(itr);
               auto ptr_before = *before;

               if(ptr_before.first + ptr_before.second > p) {
                  FUZZER_WRITE_AND_CRASH("Previous " << static_cast<void*>(ptr_before.first) << "/" << ptr_before.second
                                                     << " overlaps with new " << static_cast<void*>(p));
               }
            }

            auto after = std::next(itr);

            if(after != ptrs.end()) {
               if(p + plen > after->first) {
                  FUZZER_WRITE_AND_CRASH("New " << static_cast<void*>(p) << "/" << plen << " overlaps following "
                                                << static_cast<void*>(after->first));
               }
            }
         }
      } else if(op == 1) {
         if(ptrs.empty()) {
            continue;
         }

         size_t which_ptr = idx % ptrs.size();

         auto itr = ptrs.begin();

         while(which_ptr-- > 0) {
            ++itr;
         }

         //printf("free %p %d\n", itr->first, itr->second);
         FUZZER_ASSERT_TRUE(pool.deallocate(itr->first, itr->second));
         ptrs.erase(itr);
      }
   }
}
