/*
* Memory Locking Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mlock.h>

#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
  #include <sys/types.h>
  #include <sys/mman.h>
#elif defined(BOTAN_TARGET_OS_HAS_WIN32_VIRTUAL_LOCK)
  #include <windows.h>
#endif

namespace Botan {

bool has_mlock()
   {
   byte buf[4096];
   if(!lock_mem(&buf, sizeof(buf)))
      return false;
   unlock_mem(&buf, sizeof(buf));
   return true;
   }

/*
* Lock an area of memory into RAM
*/
bool lock_mem(void* ptr, size_t bytes)
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   return (::mlock(static_cast<char*>(ptr), bytes) == 0);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32_VIRTUAL_LOCK)
   return (::VirtualLock(ptr, bytes) != 0);
#else
   return false;
#endif
   }

/*
* Unlock a previously locked region of memory
*/
void unlock_mem(void* ptr, size_t bytes)
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   ::munlock(static_cast<char*>(ptr), bytes);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32_VIRTUAL_LOCK)
   ::VirtualUnlock(ptr, bytes);
#endif
   }

}
