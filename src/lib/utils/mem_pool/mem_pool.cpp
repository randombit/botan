/*
* (C) 2018,2019 Jack Lloyd
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
* - The allocator is allowed to return null anytime it feels like not servicing
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
* space. If a Bucket does not have any space, it sets a boolean flag m_is_full
* so that it does not need to rescan when asked again. The flag is cleared on
* first free from that bucket. If no bucket has space, but there are some free
* pages left, a free page is claimed as a new Bucket for that size. In this case
* it is pushed to the front of the list so it is first in line to service new
* requests.
*
* A deallocation also walks the list of buckets for the size and asks each
* Bucket in turn if it recognizes the pointer. When a Bucket becomes empty as a
* result of a deallocation, it is recycled back into the free pool. When this
* happens, the Buckets page goes to the end of the free list. All pages on the
* free list are marked in the MMU as noaccess, so anything touching them will
* immediately crash. They are only marked R/W once placed into a new bucket.
* Making the free list FIFO maximizes the time between the last free of a bucket
* and that page being writable again, maximizing chances of crashing after a
* use-after-free.
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

size_t choose_bucket(size_t n) {
   constexpr size_t MINIMUM_ALLOCATION = 16;
   constexpr size_t MAXIMUM_ALLOCATION = 512;

   // The typical cache line size, so distinct allocations never share a line
   constexpr size_t BUCKET_STEP = 64;

   if(n < MINIMUM_ALLOCATION || n > MAXIMUM_ALLOCATION) {
      return 0;
   }

   return BUCKET_STEP * ((n + BUCKET_STEP - 1) / BUCKET_STEP);
}

inline bool ptr_in_pool(const void* pool_ptr, size_t poolsize, const void* buf_ptr, size_t bufsize) {
   const uintptr_t pool = reinterpret_cast<uintptr_t>(pool_ptr);
   const uintptr_t buf = reinterpret_cast<uintptr_t>(buf_ptr);
   return (buf >= pool) && (buf + bufsize <= pool + poolsize);
}

class BitMap final {
   public:
      explicit BitMap(size_t bits) : m_len(bits) {
         m_bits.resize(ceil_division(bits, BITMASK_BITS));

         if(bits % BITMASK_BITS != 0) {
            m_last_mask = (static_cast<bitmask_type>(1) << (bits % BITMASK_BITS)) - 1;
         }
      }

      std::optional<size_t> find_free();

      void free(size_t bit) {
         BOTAN_ASSERT_NOMSG(bit < m_len);
         const size_t w = bit / BITMASK_BITS;
         BOTAN_ASSERT_NOMSG(w < m_bits.size());
         const bitmask_type mask = static_cast<bitmask_type>(1) << (bit % BITMASK_BITS);
         m_bits[w] = m_bits[w] & (~mask);
      }

      bool empty() const {
         for(const auto bitset : m_bits) {
            if(bitset != 0) {
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

      size_t m_len;
      bitmask_type m_main_mask = std::numeric_limits<bitmask_type>::max();
      bitmask_type m_last_mask = std::numeric_limits<bitmask_type>::max();
      std::vector<bitmask_type> m_bits;
};

std::optional<size_t> BitMap::find_free() {
   for(auto& m_bit : m_bits) {
      const bitmask_type mask = (&m_bit == &m_bits.back()) ? m_last_mask : m_main_mask;
      if((m_bit & mask) != mask) {
         // Index of the lowest clear bit; this need not be const-time
         const size_t free_bit = std::countr_zero(static_cast<bitmask_type>(~m_bit));
         const bitmask_type bmask = static_cast<bitmask_type>(1) << free_bit;
         BOTAN_ASSERT_NOMSG((m_bit & bmask) == 0);
         m_bit |= bmask;
         const auto index = static_cast<size_t>(std::distance(m_bits.data(), &m_bit));
         return BITMASK_BITS * index + free_bit;
      }
   }
   return {};
}

}  // namespace

class Bucket final {
   public:
      Bucket(uint8_t* mem, size_t mem_size, size_t item_size) :
            m_item_size(item_size),
            m_page_size(mem_size),
            m_range(mem),
            m_bitmap(mem_size / item_size),
            m_is_full(false) {}

      uint8_t* alloc() {
         if(m_is_full) {
            // I know I am full
            return nullptr;
         }

         auto offset = m_bitmap.find_free();
         if(!offset) {
            // I just found out I am full
            m_is_full = true;
            return nullptr;
         } else {
            BOTAN_ASSERT(*offset * m_item_size < m_page_size, "Offset is in range");
            return m_range + m_item_size * (*offset);
         }
      }

      bool free(void* p) {
         if(!in_this_bucket(p)) {
            return false;
         }

         /*
         Zero also any trailing bytes, which should not have been written to,
         but maybe the user was bad and wrote past the end.
         */
         std::memset(p, 0, m_item_size);

         const size_t offset = (reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(m_range)) / m_item_size;

         m_bitmap.free(offset);
         m_is_full = false;

         return true;
      }

      bool in_this_bucket(void* p) const { return ptr_in_pool(m_range, m_page_size, p, m_item_size); }

      bool empty() const { return m_bitmap.empty(); }

      uint8_t* ptr() const { return m_range; }

   private:
      size_t m_item_size;
      size_t m_page_size;
      uint8_t* m_range;
      BitMap m_bitmap;
      bool m_is_full;
};

Memory_Pool::Memory_Pool(const std::vector<void*>& pages, size_t page_size) : m_page_size(page_size) {
   for(auto* page : pages) {
      const uintptr_t p = reinterpret_cast<uintptr_t>(page);

      m_min_page_ptr = std::min(p, m_min_page_ptr);
      m_max_page_ptr = std::max(p, m_max_page_ptr);

      clear_bytes(page, m_page_size);
#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
      OS::page_prohibit_access(page);
#endif
      m_free_pages.push_back(static_cast<uint8_t*>(page));
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
   for(auto* page : m_free_pages) {
      OS::page_allow_access(page);
   }
#endif
}

void* Memory_Pool::allocate(size_t n) {
   if(n > m_page_size) {
      return nullptr;
   }

   const size_t n_bucket = choose_bucket(n);

   if(n_bucket > 0) {
      const lock_guard_type<mutex_type> lock(m_mutex);

      std::deque<Bucket>& buckets = m_buckets_for[n_bucket];

      /*
      It would be optimal to pick the bucket with the most usage,
      since a bucket with say 1 item allocated out of it has a high
      chance of becoming later freed and then the whole page can be
      recycled.
      */
      for(auto& bucket : buckets) {
         // NOLINTNEXTLINE(*-const-correctness) bug in clang-tidy
         if(uint8_t* p = bucket.alloc()) {
            return p;
         }

         // If the bucket is full, maybe move it to the end of the list?
         // Otoh bucket search should be very fast
      }

      if(!m_free_pages.empty()) {
         uint8_t* ptr = m_free_pages[0];
         m_free_pages.pop_front();
#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
         OS::page_allow_access(ptr);
#endif
         buckets.push_front(Bucket(ptr, m_page_size, n_bucket));
         // NOLINTNEXTLINE(*-const-correctness) bug in clang-tidy
         void* p = buckets[0].alloc();
         BOTAN_ASSERT_NOMSG(p != nullptr);
         return p;
      }
   }

   // out of room
   return nullptr;
}

bool Memory_Pool::deallocate(void* p, size_t len) noexcept {
   // Do a fast range check first, before taking the lock
   const uintptr_t p_val = reinterpret_cast<uintptr_t>(p);
   if(p_val < m_min_page_ptr || p_val > m_max_page_ptr) {
      return false;
   }

   const size_t n_bucket = choose_bucket(len);

   if(n_bucket != 0) {
      try {
         const lock_guard_type<mutex_type> lock(m_mutex);

         std::deque<Bucket>& buckets = m_buckets_for[n_bucket];

         for(size_t i = 0; i != buckets.size(); ++i) {
            Bucket& bucket = buckets[i];
            if(bucket.free(p)) {
               if(bucket.empty()) {
#if defined(BOTAN_MEM_POOL_USE_MMU_PROTECTIONS)
                  OS::page_prohibit_access(bucket.ptr());
#endif
                  m_free_pages.push_back(bucket.ptr());

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
