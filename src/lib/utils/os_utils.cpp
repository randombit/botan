/*
* OS and machine specific utility functions
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/os_utils.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>

//TODO: defined(BOTAN_TARGET_OS_TYPE_IS_POSIX)

#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
  #define BOTAN_TARGET_OS_HAS_POSIX_2008
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
  #include <sys/types.h>
  #include <sys/mman.h>
  #include <sys/resource.h>
  #include <unistd.h>
#endif

namespace Botan {

namespace OS {

uint32_t get_process_id()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_2008)
   return ::getpid();
#elif defined(BOTAN_TARGET_OS_HAS_WIN32_API)
   return ::GetProcessId();
#else
   return 0;
#endif
   }

size_t get_memory_locking_limit()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_2008)
   /*
   * Linux defaults to only 64 KiB of mlockable memory per process
   * (too small) but BSDs offer a small fraction of total RAM (more
   * than we need). Bound the total mlock size to 512 KiB which is
   * enough to run the entire test suite without spilling to non-mlock
   * memory (and thus presumably also enough for many useful
   * programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   size_t mlock_requested = BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB;

   /*
   * Allow override via env variable
   */
   if(const char* env = ::getenv("BOTAN_MLOCK_POOL_SIZE"))
      {
      try
         {
         const size_t user_req = std::stoul(env, nullptr);
         mlock_requested = std::min(user_req, mlock_requested);
         }
      catch(std::exception&) { /* ignore it */ }
      }

   if(mlock_requested > 0)
      {
      struct ::rlimit limits;

      ::getrlimit(RLIMIT_MEMLOCK, &limits);

      if(limits.rlim_cur < limits.rlim_max)
         {
         limits.rlim_cur = limits.rlim_max;
         ::setrlimit(RLIMIT_MEMLOCK, &limits);
         ::getrlimit(RLIMIT_MEMLOCK, &limits);
         }

      return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
      }
#endif

   return 0;
   }

void* allocate_locked_pages(size_t length)
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_2008)

#if !defined(MAP_NOCORE)
   #define MAP_NOCORE 0
#endif

#if !defined(MAP_ANONYMOUS)
   #define MAP_ANONYMOUS MAP_ANON
#endif

   void* ptr = ::mmap(nullptr,
                      length,
                      PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
                      /*fd*/-1,
                      /*offset*/0);

   if(ptr == MAP_FAILED)
      {
      return nullptr;
      }

#if defined(MADV_DONTDUMP)
   ::madvise(ptr, length, MADV_DONTDUMP);
#endif

   if(::mlock(ptr, length) != 0)
      {
      ::munmap(ptr, length);
      return nullptr; // failed to lock
      }

   ::memset(ptr, 0, length);

   return ptr;
#else
   return nullptr; /* not implemented */
#endif
   }

void free_locked_pages(void* ptr, size_t length)
   {
   if(ptr == nullptr || length == 0)
      return;

#if defined(BOTAN_TARGET_OS_HAS_POSIX_2008)
   zero_mem(ptr, length);
   ::munlock(ptr, length);
   ::munmap(ptr, length);
#else
   // Invalid argument because no way this pointer was allocated by us
   throw Invalid_Argument("Invalid ptr to free_locked_pages");
#endif
   }

}

}
