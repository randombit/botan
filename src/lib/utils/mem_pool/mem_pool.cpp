/*
* (C) 2018,2019 Jack Lloyd
* (C) 2026 Gent Binaku
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mem_pool.h>

#include <botan/mem_ops.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/target_info.h>
#include <algorithm>
#include <bit>
#include <exception>
#include <limits>
#include <optional>
#include <vector>

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <functional>
   #include <thread>
#endif

#if defined(BOTAN_HAS_VALGRIND) || defined(BOTAN_ENABLE_DEBUG_ASSERTS)
   /**
    * @brief Prohibits access to unused memory pages in Botan's memory pool
    *
    * If BOTAN_MEM_POOL_USE_MMU_PROTECTIONS is defined, the Memory_Pool
    * class used for mlock'ed memory will use OS calls to set page
    * permissions so as to prohibit access to pages on the free list, then
    * enable read/write access when the page is set to be used. This will
    * turn (some) use after free bugs into a crash.
    *
    * The additional syscalls have a substantial performance impact, which
    * is why this option is not enabled by default. It is used when built for
    * running in valgrind or debug assertions are enabled.
    */
   #define BOTAN_MEM_POOL_USE_MMU_PROTECTIONS
#endif

#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS) && defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan {

/*
* Memory pool theory of operation
*
* This allocator is not useful for general purpose but works well within the
* context of allocating cryptographic keys. It makes several assumptions which
* don't work for implementing malloc but simplify and speed up the implementation:
*
* - There is some set of pages, which cannot be expanded later. These are pages
*   which were allocated, mlocked and passed to the Memory_Pool constructor.
*
* - The allocator is allowed to return an empty span anytime it feels like not servicing
*   a request, in which case the request will be sent to calloc instead. In
*   particular, requests which are too small or too large are rejected.
*
* - Free requests include the size of the allocation, so there is no need to
*   track this within the pool.
*
* - Alignment is important to the caller. For this allocator, every allocation
*   is aligned to 64 bytes.
*
* Initially each page is in the free page list. Each page is used for just one
* size of allocation, with requests rounded up to a multiple of 64 bytes so that
* no two allocations share a cache line. If the allocation would be too big or
* too small it is rejected by the pool.
*
* The free list is maintained by a bitmap, one per page/Bucket. Since each
* Bucket only maintains objects of a single size, each bit set or clear
* indicates the status of one object.
*
* An allocation walks the list of buckets and asks each in turn if there is
* space. The walk starts at a per-thread index (see thread_index) and wraps
* around, so that different threads tend to start in different buckets. If a
* Bucket does not have any space, it sets a boolean flag m_is_full so that it
* does not need to rescan when asked again. The flag is cleared on first free
* from that bucket. If no bucket has space, but there are some free pages left,
* a free page is claimed as a new Bucket for that size and appended to the list.
*
* A deallocation also walks the list of buckets for the size and asks each
* Bucket in turn if it recognizes the pointer. When a Bucket becomes empty as a
* result of a deallocation, it is recycled back into the free pool. All pages
* on the free list are marked in the MMU as noaccess, so anything touching them
* will immediately crash. They are only marked R/W once placed into a new bucket.
*
* Deallocation must never allocate, since it is noexcept and any exception
* leads to std::terminate. The free list is therefore a vector reserved in the
* constructor to hold every page, so returning a page to it never reallocates.
* It is used as a stack: the most recently freed page is reused first. A FIFO
* would maximize the time between the last free of a bucket and that page being
* writable again, catching more use-after-free bugs, at the cost of a more
* complex fixed-capacity queue.
*
* Future work
* -------------
*
* The allocator is protected by a global lock. It would be good to break this
* up, since almost all of the work can actually be done in parallel especially
* when allocating objects of different sizes (which can't possibly share a
* bucket).
*
* It may be worthwhile to optimize deallocation by storing the Buckets in order
* (by pointer value) which would allow binary search to find the owning bucket.
*
* A useful addition would be to randomize the allocations. Memory_Pool would be
* changed to receive also a RandomNumberGenerator& object (presumably the system
* RNG, or maybe a ChaCha_RNG seeded with system RNG). Then the bucket to use and
* the offset within the bucket would be chosen randomly, instead of using first fit.
*
* Supporting a realloc-style API may be useful.
*/

namespace {

// Slot size for a request of n bytes, or 0 if the pool does not serve it
size_t choose_bucket(size_t n) {
   if(n < Memory_Pool::MINIMUM_ALLOCATION || n > Memory_Pool::MAXIMUM_ALLOCATION) {
      return 0;
   }

   return Memory_Pool::BUCKET_STEP * ceil_division(n, Memory_Pool::BUCKET_STEP);
}

// Index into m_buckets_for for a nonzero slot size returned by choose_bucket
size_t size_class_index(size_t slot_size) {
   BOTAN_ASSERT_NOMSG(slot_size > 0 && slot_size % Memory_Pool::BUCKET_STEP == 0);
   return slot_size / Memory_Pool::BUCKET_STEP - 1;
}

/*
* A per-thread value in [0, count) used as the starting point when searching
* for a free bucket. Each thread always starts from the same place, so its
* allocations tend to cluster together instead of being interleaved with
* those of other threads. This is only a placement hint; any thread may
* use or free any slot.
*/
size_t thread_index(size_t count) {
   if(count == 0) {
      return 0;
   }

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   const uint64_t thread_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
   // 2^64 / golden ratio (Fibonacci hashing)
   constexpr uint64_t FIBONACCI_MULTIPLIER = 0x9E3779B97F4A7C15ULL;
   // The low bits of the product are poorly mixed, use the high ones
   return static_cast<size_t>((thread_hash * FIBONACCI_MULTIPLIER) >> 32) % count;
#else
   return 0;
#endif
}

class BitMap final {
   public:
      explicit BitMap(size_t bits) : m_bit_count(bits) {
         m_bits.resize(ceil_division(bits, BITMASK_BITS));

         if(bits % BITMASK_BITS != 0) {
            m_last_mask = (static_cast<bitmask_type>(1) << (bits % BITMASK_BITS)) - 1;
         }
      }

      std::optional<size_t> find_free();

      void free(size_t bit) {
         BOTAN_ASSERT_NOMSG(bit < m_bit_count);
         const size_t word_index = bit / BITMASK_BITS;
         BOTAN_ASSERT_NOMSG(word_index < m_bits.size());
         const bitmask_type bit_mask = static_cast<bitmask_type>(1) << (bit % BITMASK_BITS);
         m_bits[word_index] &= ~bit_mask;
      }

      bool empty() const {
         for(const auto word : m_bits) {
            if(word != 0) {
               return false;
            }
         }

         return true;
      }

   private:
#if defined(BOTAN_ENABLE_DEBUG_ASSERTS)
      using bitmask_type = uint8_t;
#else
      using bitmask_type = word;
#endif

      static const size_t BITMASK_BITS = sizeof(bitmask_type) * 8;

      size_t m_bit_count;
      bitmask_type m_main_mask = std::numeric_limits<bitmask_type>::max();
      bitmask_type m_last_mask = std::numeric_limits<bitmask_type>::max();
      std::vector<bitmask_type> m_bits;
};

std::optional<size_t> BitMap::find_free() {
   for(auto& word : m_bits) {
      const bitmask_type mask = (&word == &m_bits.back()) ? m_last_mask : m_main_mask;
      if((word & mask) != mask) {
         // Index of the lowest clear bit; this need not be const-time
         const size_t free_bit = std::countr_zero(static_cast<bitmask_type>(~word));
         const bitmask_type bit_mask = static_cast<bitmask_type>(1) << free_bit;
         BOTAN_ASSERT_NOMSG((word & bit_mask) == 0);
         word |= bit_mask;
         const auto word_index = static_cast<size_t>(std::distance(m_bits.data(), &word));
         // slot = (number of complete words before this one) × (slots per word) + (position within this word)
         return BITMASK_BITS * word_index + free_bit;
      }
   }
   return {};
}

}  // namespace

class Bucket final {
   public:
      Bucket(std::span<uint8_t> page, size_t item_size) :
            m_item_size(item_size), m_page(page), m_bitmap(page.size() / item_size), m_is_full(false) {}

      std::span<uint8_t> alloc() {
         if(m_is_full) {
            // I know I am full
            return {};
         }

         const auto slot_index = m_bitmap.find_free();
         if(slot_index.has_value()) {
            BOTAN_ASSERT(*slot_index * m_item_size < m_page.size(), "Offset is in range");
            return m_page.subspan(*slot_index * m_item_size, m_item_size);
         } else {
            // I just found out I am full
            m_is_full = true;
            return {};
         }
      }

      bool free(std::span<uint8_t> buf) {
         const auto byte_offset = offset_of(buf.data());
         if(!byte_offset.has_value()) {
            return false;
         }

         /*
         Zero also any trailing bytes, which should not have been written to,
         but maybe the user was bad and wrote past the end.
         */
         const auto slot = m_page.subspan(*byte_offset, m_item_size);
         std::memset(slot.data(), 0, slot.size());

         m_bitmap.free(*byte_offset / m_item_size);
         m_is_full = false;

         return true;
      }

      bool in_this_bucket(const void* p) const { return offset_of(p).has_value(); }

      bool empty() const { return m_bitmap.empty(); }

      std::span<uint8_t> page() const { return m_page; }

   private:
      /**
      * Byte offset of p within this bucket's page, or nullopt if an item
      * starting at p would not fit entirely inside the page.
      */
      std::optional<size_t> offset_of(const void* p) const {
         // Compare as integers: p may point outside the page, and relational
         // comparison of unrelated pointers is unspecified.
         const uintptr_t start = reinterpret_cast<uintptr_t>(m_page.data());
         const uintptr_t addr = reinterpret_cast<uintptr_t>(p);
         if(addr < start) {
            return std::nullopt;
         }
         const size_t offset = addr - start;
         if(offset > m_page.size() || m_item_size > m_page.size() - offset) {
            return std::nullopt;
         }
         return offset;
      }

      size_t m_item_size;
      std::span<uint8_t> m_page;
      BitMap m_bitmap;
      bool m_is_full;
};

Memory_Pool::Memory_Pool(const std::vector<std::span<uint8_t>>& pages, size_t page_size) : m_page_size(page_size) {
   m_free_pages.reserve(pages.size());
   for(const auto& page : pages) {
      BOTAN_ARG_CHECK(page.size() == page_size, "Each page must be exactly page_size bytes");

      const uintptr_t addr = reinterpret_cast<uintptr_t>(page.data());
      m_min_page_ptr = std::min(addr, m_min_page_ptr);
      m_max_page_ptr = std::max(addr, m_max_page_ptr);

      std::fill(page.begin(), page.end(), 0);

#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
      OS::page_prohibit_access(page.data());
#endif
      m_free_pages.push_back(page);
   }

   /*
   Right now this points to the start of the last page, adjust it to instead
   point to the first byte of the following page
   */
   m_max_page_ptr += page_size;
}

Memory_Pool::~Memory_Pool() noexcept  // NOLINT(*-use-equals-default)
{
#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
   for(const auto& page : m_free_pages) {
      OS::page_allow_access(page.data());
   }
#endif
}

std::span<uint8_t> Memory_Pool::allocate(size_t n) {
   if(n > m_page_size) {
      return {};
   }

   const size_t slot_size = choose_bucket(n);

   if(slot_size > 0) {
      const lock_guard_type<mutex_type> lock(m_mutex);

      std::vector<Bucket>& buckets = m_buckets_for[size_class_index(slot_size)];

      /*
      It would be optimal to pick the bucket with the most usage,
      since a bucket with say 1 item allocated out of it has a high
      chance of becoming later freed and then the whole page can be
      recycled.
      */
      const size_t start = thread_index(buckets.size());
      for(size_t i = 0; i != buckets.size(); ++i) {
         Bucket& bucket = buckets[(start + i) % buckets.size()];
         if(const auto slot = bucket.alloc(); !slot.empty()) {
            return slot.first(n);
         }
      }

      if(!m_free_pages.empty()) {
         const auto page = m_free_pages.back();
         m_free_pages.pop_back();
#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
         OS::page_allow_access(page.data());
#endif
         buckets.push_back(Bucket(page, slot_size));

         // The bucket we just created is empty, so allocate from it
         const auto slot = buckets.back().alloc();
         BOTAN_ASSERT_NOMSG(!slot.empty());
         return slot.first(n);
      }
   }

   // out of room
   return {};
}

bool Memory_Pool::deallocate(std::span<uint8_t> buf) noexcept {
   // Do a fast range check first, before taking the lock
   const uintptr_t addr = reinterpret_cast<uintptr_t>(buf.data());
   if(addr < m_min_page_ptr || addr >= m_max_page_ptr) {
      return false;
   }
   const size_t slot_size = choose_bucket(buf.size());
   if(slot_size != 0) {
      try {
         const lock_guard_type<mutex_type> lock(m_mutex);
         std::vector<Bucket>& buckets = m_buckets_for[size_class_index(slot_size)];

         for(size_t i = 0; i != buckets.size(); ++i) {
            Bucket& bucket = buckets[i];
            if(bucket.free(buf)) {
               if(bucket.empty()) {
#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
                  OS::page_prohibit_access(bucket.page().data());
#endif
                  m_free_pages.push_back(bucket.page());

                  if(i != buckets.size() - 1) {
                     std::swap(buckets.back(), buckets[i]);
                  }
                  buckets.pop_back();
               }
               return true;
            }
         }
      } catch(...) {
         /*
         * The only exception throws that can occur in the above code are from
         * either the STL or BOTAN_ASSERT failures. In either case, such an
         * error indicates a logic error or data corruption in the memory
         * allocator such that it is no longer safe to continue executing.
         *
         * Since this function is noexcept, simply letting the exception escape
         * is sufficient for terminate to be called. However in this scenario
         * it is implementation defined if any stack unwinding is performed.
         * Since stack unwinding could cause further memory deallocations this
         * could result in further corruption in this allocator state. To prevent
         * this, call terminate directly.
         */
         std::terminate();
      }
   }

   return false;
}

}  // namespace Botan
