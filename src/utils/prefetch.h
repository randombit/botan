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

namespace PREFETCH {

template<typename T>
inline void readonly(const T* addr, u32bit length)
   {
#if defined(__GNUG__)
   const u32bit Ts_per_cache_line = CPUID::cache_line_size() / sizeof(T);

   for(u32bit i = 0; i <= length; i += Ts_per_cache_line)
      __builtin_prefetch(addr + i, 0);
#endif
   }

template<typename T>
inline void readwrite(const T* addr, u32bit length)
   {
#if defined(__GNUG__)
   const u32bit Ts_per_cache_line = CPUID::cache_line_size() / sizeof(T);

   for(u32bit i = 0; i <= length; i += Ts_per_cache_line)
      __builtin_prefetch(addr + i, 0);
#endif
   }

inline void cipher_fetch(const byte* in_block,
                         const byte* out_block,
                         u32bit blocks,
                         u32bit block_size)
   {
   // Only prefetch input specifically if in != out
   if(in_block != out_block)
      readonly(in_block, blocks * block_size);

   readwrite(out_block, blocks * block_size);
   }

}

}

#endif
