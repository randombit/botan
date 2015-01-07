/*
* Zero Memory
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mem_ops.h>

#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
  #include <windows.h>
#elif defined(BOTAN_TARGET_OS_HAS_MEMSET_S)
  #define __STDC_WANT_LIB_EXT1__ 1
  #include <string.h>
#endif

namespace Botan {

void zero_mem(void* ptr, size_t n)
   {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);
#elif defined(BOTAN_TARGET_OS_HAS_MEMSET_S)
   ::memset_s(ptr, n, 0, n);
#else
   volatile byte* p = reinterpret_cast<volatile byte*>(ptr);

   for(size_t i = 0; i != n; ++i)
      p[i] = 0;
#endif
   }

}
