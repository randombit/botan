 /*
* Zero Memory
* (C) 2012,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mem_ops.h>

#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
  #include <windows.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_MEMSET_S)
  // We must include string.h in addition to cstring because memset_s
  // is only part of C11, not C++11.
  #include <string.h>
#endif

namespace Botan {

void zero_mem(void* ptr, size_t n)
   {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);
#elif defined(BOTAN_TARGET_OS_HAS_MEMSET_S)
   ::memset_s(ptr, n, 0, n);
#elif defined(BOTAN_USE_VOLATILE_MEMSET) && (BOTAN_USE_VOLATILE_MEMSET == 1)
   static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
   (memset_ptr)(p, 0, n);
#else
   volatile byte* p = reinterpret_cast<volatile byte*>(ptr);

   for(size_t i = 0; i != n; ++i)
      p[i] = 0;
#endif
   }

}
