/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mem_pool.h>
#include <botan/mem_ops.h>

namespace Botan {

/*
* Memory pool theory of operation
*
* This allocator is not useful for general purpose but works well within the
* context of allocating cryptographic keys. It makes several assumptions which
* don't work for a malloc but simplify and speed up the implementation:
*
* - There is a single fixed block of memory, which cannot be expanded.  This is
*   the block that was allocated, mlocked and passed to the Memory_Pool
*   constructor. It is assumed to be page-aligned.
*
* - The allocator is allowed to return null anytime it feels like not servicing
*   a request, in which case the request will be sent to calloc instead. In
*   particular values which are too small or too large are given to calloc.
*
* - Most allocations are powers of 2, the remainder are usually a multiple of 4
*   or 8.
*
* - Free requests include the size of the allocation, so there is no need to
*   track this within the pool.
*
* - Alignment is important to the caller. For this allocator, any allocation of
*   size N is aligned evenly at N bytes.
*
* The block of memory is split up into pages. Initially each page is in the free
* page list. Each page is used for just one size of allocation, with requests
* bucketed into a small number of common sizes. If the allocation would be too
* big, too small, or with too much slack, it is rejected by the pool.
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
* happens, the Buckets pointer goes to the end of the free list. This will delay
* slightly the reuse of this page, which may offer some slight help wrt use
* after free issues.
*
* It may be worthwhile to optimize deallocation by storing the Buckets in order
* (by pointer value) which would allow binary search to find the owning bucket.
*/

namespace {

size_t choose_bucket(size_t n)
   {
   const size_t MINIMUM_ALLOCATION = 16;
   const size_t MAXIMUM_ALLOCATION = 512;
   const size_t MAXIMUM_SLACK = 31;

   if(n < MINIMUM_ALLOCATION|| n > MAXIMUM_ALLOCATION)
      return 0;

   // Need to tune these
   const size_t buckets[] = {
      16, 24, 32, 48, 64, 80, 96, 112, 128, 160, 192, 256, 320, 384, 448, 512, 0
   };

   for(size_t i = 0; buckets[i]; ++i)
      {
      if(n <= buckets[i])
         {
         const size_t slack = buckets[i] - n;
         if(slack > MAXIMUM_SLACK)
            return 0;
         return buckets[i];
         }
      }

   return 0;
   }

inline bool ptr_in_pool(const void* pool_ptr, size_t poolsize,
                        const void* buf_ptr, size_t bufsize)
   {
   const uintptr_t pool = reinterpret_cast<uintptr_t>(pool_ptr);
   const uintptr_t buf = reinterpret_cast<uintptr_t>(buf_ptr);
   return (buf >= pool) && (buf + bufsize <= pool + poolsize);
   }

// return index of first set bit
template<typename T>
size_t find_set_bit(T b)
   {
   size_t s = 8*sizeof(T) / 2;
   size_t bit = 0;

   // In this context we don't need to be const-time
   while(s > 0)
      {
      const T mask = (static_cast<T>(1) << s) - 1;
      if((b & mask) == 0)
         {
         bit += s;
         b >>= s;
         }
      s /= 2;
      }

   return bit;
   }

class BitMap final
   {
   public:
      BitMap(size_t bits) : m_len(bits)
         {
         m_bits.resize((bits + BITMASK_BITS - 1) / BITMASK_BITS);
         m_main_mask = ~static_cast<bitmask_type>(0);
         m_last_mask = m_main_mask;

         if(bits % BITMASK_BITS != 0)
            m_last_mask = (static_cast<bitmask_type>(1) << (bits % BITMASK_BITS)) - 1;
         }

      bool find_free(size_t* bit);

      void free(size_t bit);

      bool empty() const;

  private:
#if defined(BOTAN_ENABLE_DEBUG_ASSERTS)
      typedef uint8_t bitmask_type;
      enum { BITMASK_BITS = 8 };
#else
      typedef word bitmask_type;
      enum { BITMASK_BITS = BOTAN_MP_WORD_BITS };
#endif

      size_t m_len;
      bitmask_type m_main_mask;
      bitmask_type m_last_mask;
      std::vector<bitmask_type> m_bits;
   };

bool BitMap::find_free(size_t* bit)
   {
   for(size_t i = 0; i != m_bits.size(); ++i)
      {
      const bitmask_type mask = (i == m_bits.size() - 1) ? m_last_mask : m_main_mask;
      if((m_bits[i] & mask) != mask)
         {
         size_t free_bit = find_set_bit(~m_bits[i]);
         const size_t bmask = static_cast<bitmask_type>(1) << (free_bit % BITMASK_BITS);
         BOTAN_ASSERT_NOMSG((m_bits[i] & bmask) == 0);
         m_bits[i] |= bmask;
         *bit = BITMASK_BITS*i + free_bit;
         return true;
         }
      }

   return false;
   }

void BitMap::free(size_t bit)
   {
   BOTAN_ASSERT_NOMSG(bit <= m_len);
   const size_t w = bit / BITMASK_BITS;
   BOTAN_ASSERT_NOMSG(w < m_bits.size());
   const size_t mask = static_cast<bitmask_type>(1) << (bit % BITMASK_BITS);
   m_bits[w] = m_bits[w] & (~mask);
   }

bool BitMap::empty() const
   {
   for(size_t i = 0; i != m_bits.size(); ++i)
      {
      if(m_bits[i] != 0)
         {
         return false;
         }
      }

   return true;
   }

}

class Bucket final
   {
   public:
      Bucket(uint8_t* mem, size_t mem_size, size_t item_size) :
         m_item_size(item_size),
         m_page_size(mem_size),
         m_range(mem),
         m_bitmap(mem_size / item_size),
         m_is_full(false)
         {
         }

      uint8_t* alloc();

      bool free(void* p);

      bool in_this_bucket(void* p) const
         {
         return ptr_in_pool(m_range, m_page_size, p, m_item_size);
         }

      bool empty() const
         {
         return m_bitmap.empty();
         }

      uint8_t* ptr() const
         {
         return m_range;
         }


   private:
      size_t m_item_size;
      size_t m_page_size;
      uint8_t* m_range;
      BitMap m_bitmap;
      bool m_is_full;
   };


uint8_t* Bucket::alloc()
   {
   if(m_is_full)
      {
      // I know I am full
      return nullptr;
      }

   size_t offset;
   if(!m_bitmap.find_free(&offset))
      {
      // I just found out I am full
      m_is_full = true;
      return nullptr;
      }

   BOTAN_ASSERT(offset * m_item_size < m_page_size, "Offset is in range");
   return m_range + m_item_size*offset;
   }

bool Bucket::free(void* p)
   {
   if(!in_this_bucket(p))
      return false;

   const size_t offset = (reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(m_range)) / m_item_size;

   m_bitmap.free(offset);
   m_is_full = false;

   return true;
   }

Memory_Pool::Memory_Pool(uint8_t* pool, size_t num_pages, size_t page_size) :
   m_page_size(page_size)
   {
   BOTAN_ARG_CHECK(pool != nullptr, "Memory_Pool pool was null");

   // This is basically just to verify that the range is valid
   clear_mem(pool, num_pages * page_size);

   m_pool = pool;
   m_pool_size = num_pages * page_size;

   for(size_t i = 0; i != num_pages; ++i)
      {
      m_free_pages.push_back(pool + page_size*i);
      }
   }

Memory_Pool::~Memory_Pool()
   {
   }

void* Memory_Pool::allocate(size_t n)
   {
   if(n > m_page_size)
      return nullptr;

   const size_t n_bucket = choose_bucket(n);

   if(n_bucket == 0)
      return nullptr;

   lock_guard_type<mutex_type> lock(m_mutex);

   std::deque<Bucket>& buckets = m_buckets_for[n_bucket];

   for(auto& bucket : buckets)
      {
      if(uint8_t* p = bucket.alloc())
         return p;

      // If the bucket is full, maybe move it to the end of the list?
      // Otoh bucket search should be very fast
      }

   if(m_free_pages.size() > 0)
      {
      uint8_t* ptr = m_free_pages[0];
      m_free_pages.pop_front();
      buckets.push_front(Bucket(ptr, m_page_size, n_bucket));
      void* p = buckets[0].alloc();
      BOTAN_ASSERT_NOMSG(p != nullptr);
      return p;
      }

   // out of room
   return nullptr;
   }

bool Memory_Pool::deallocate(void* p, size_t len) noexcept
   {
   if(!ptr_in_pool(m_pool, m_pool_size, p, len))
      return false;

   const size_t n_bucket = choose_bucket(len);

   if(n_bucket != 0)
      {
      /*
      Zero also any trailing bytes, which should not have been written to,
      but maybe the user was bad and wrote past the end.
      */
      std::memset(p, 0, n_bucket);

      lock_guard_type<mutex_type> lock(m_mutex);

      std::deque<Bucket>& buckets = m_buckets_for[n_bucket];

      for(size_t i = 0; i != buckets.size(); ++i)
         {
         Bucket& bucket = buckets[i];
         if(bucket.free(p) == false)
            continue;

         if(bucket.empty())
            {
            m_free_pages.push_back(bucket.ptr());

            if(i != buckets.size() - 1)
               std::swap(buckets.back(), buckets[i]);
            buckets.pop_back();
            }

         return true;
         }
      }

   /*
   * If we reach this point, something bad has occurred. We know the pointer
   * passed in is inside the range of the pool, but no bucket recognized it,
   * either because n_bucket was zero or no Bucket::free call returned true. Our
   * options (since this function is noexcept) are to either ignore it and
   * return false, ignore it and return true, or to crash.
   *
   * Returning false means the pointer will be considered a standard heap
   * pointer and passed on to free, which will almost certainly cause a heap
   * corruption.
   *
   * There is some robustness argument for just memseting the pointer and
   * returning true. In this case it will be assumed to be freed. But, since
   * this pointer *is* within the range of the pool, but no bucket claimed it,
   * that seems to indicate some existing allocator corruption.
   *
   * Crashing is bad, heap corruption is worse. So we crash, in this case by
   * calling BOTAN_ASSERT and letting the exception handling mechanism
   * terminate the process.
   */
   BOTAN_ASSERT(false, "Pointer from pool, but no bucket recognized it");
   return false;
   }

}
