/*
* Prefetching Operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PREFETCH_H__
#define BOTAN_PREFETCH_H__

#include <botan/cpuid.h>

namespace Botan {

inline void prefetch_readonly(const void* addr_void, u32bit length)
   {
#if defined(__GNUG__)
   const byte* addr = static_cast<const byte*>(addr_void);
   const u32bit cl_size = CPUID::cache_line_size();

   for(u32bit i = 0; i <= length; i += cl_size)
      __builtin_prefetch(addr + i, 0);
#endif
   }

inline void prefetch_readwrite(const void* addr_void, u32bit length)
   {
#if defined(__GNUG__)
   const byte* addr = static_cast<const byte*>(addr_void);
   const u32bit cl_size = CPUID::cache_line_size();

   for(u32bit i = 0; i <= length; i += cl_size)
      __builtin_prefetch(addr + i, 1);
#endif
   }

}

#endif
