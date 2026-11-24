/*
* (C) 2026 Gent Binaku
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MEM_POOL) && defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/mem_pool.h>
   #include <botan/internal/os_utils.h>
   #include <cstdlib>
   #include <new>
   #include <span>
   #include <vector>
#endif

#if defined(BOTAN_HAS_MEM_POOL) && defined(BOTAN_HAS_OS_UTILS)

namespace {

/*
* Count heap allocations made by this thread while armed. Memory_Pool::deallocate
* is noexcept and calls std::terminate if anything inside it throws, so it must
* never allocate (GH #6149). Counting instead of throwing bad_alloc lets the test
* report a failure rather than abort the whole test run.
*/
// NOLINTBEGIN(*-avoid-non-const-global-variables)
thread_local bool g_count_allocations = false;
thread_local size_t g_allocations = 0;
// NOLINTEND(*-avoid-non-const-global-variables)

void* counting_malloc(std::size_t size) {
   if(g_count_allocations) {
      ++g_allocations;
   }
   if(size == 0) {
      size = 1;
   }
   for(;;) {
      // NOLINTNEXTLINE(*-no-malloc,*-owning-memory)
      if(void* p = std::malloc(size)) {
         return p;
      }
      std::new_handler handler = std::get_new_handler();
      if(handler == nullptr) {
         throw std::bad_alloc();
      }
      handler();
   }
}

}  // namespace

// NOLINTBEGIN(*-no-malloc,*-owning-memory)
void* operator new(std::size_t size) {
   return counting_malloc(size);
}

void* operator new[](std::size_t size) {
   return counting_malloc(size);
}

void operator delete(void* p) noexcept {
   std::free(p);
}

void operator delete[](void* p) noexcept {
   std::free(p);
}

void operator delete(void* p, std::size_t /*size*/) noexcept {
   std::free(p);
}

void operator delete[](void* p, std::size_t /*size*/) noexcept {
   std::free(p);
}

// NOLINTEND(*-no-malloc,*-owning-memory)

#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_MEM_POOL) && defined(BOTAN_HAS_OS_UTILS)

namespace {

class Memory_Pool_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override { return {test_deallocate_does_not_allocate()}; }

   private:
      static Test::Result test_deallocate_does_not_allocate() {
         Test::Result result("Memory_Pool deallocate does not allocate");

         constexpr size_t page_count = 4;
         const size_t page_size = Botan::OS::system_page_size();

         // One extra page so we can align the start to a page boundary
         std::vector<uint8_t> backing((page_count + 1) * page_size);
         const uintptr_t base = reinterpret_cast<uintptr_t>(backing.data());
         const size_t skip = (page_size - (base % page_size)) % page_size;

         std::vector<std::span<uint8_t>> pages;
         for(size_t i = 0; i != page_count; ++i) {
            pages.push_back(std::span{backing}.subspan(skip + i * page_size, page_size));
         }

         // Declared after backing so it is destroyed first (it restores page access)
         Botan::Memory_Pool pool(pages, page_size);

         /*
         * Every iteration takes a page off the free list and, on deallocate,
         * the now empty bucket hands its page back. A std::deque grows a new
         * block every few push_backs, so a few hundred rounds is plenty to
         * hit that if the free list can allocate.
         */
         size_t allocations_in_deallocate = 0;
         for(size_t i = 0; i != 256; ++i) {
            const auto buf = pool.allocate(64);
            if(!result.test_is_false("allocate succeeded", buf.empty())) {
               break;
            }

            g_allocations = 0;
            g_count_allocations = true;
            const bool released = pool.deallocate(buf);
            g_count_allocations = false;
            allocations_in_deallocate += g_allocations;

            if(!result.test_is_true("deallocate released the buffer", released)) {
               break;
            }
         }

         result.test_sz_eq("heap allocations inside deallocate", allocations_in_deallocate, 0);
         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "mem_pool", Memory_Pool_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
