/*
* Memory Operations
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MEMORY_OPS_H__
#define BOTAN_MEMORY_OPS_H__

#include <botan/types.h>
#include <cstring>

namespace Botan {

/*
* Memory Manipulation Functions
*/
template<typename T> inline void copy_mem(T* out, const T* in, u32bit n)
   { std::memmove(out, in, sizeof(T)*n); }

template<typename T> inline void clear_mem(T* ptr, u32bit n)
   { if(n) std::memset(ptr, 0, sizeof(T)*n); }

template<typename T> inline void set_mem(T* ptr, u32bit n, byte val)
   { std::memset(ptr, val, sizeof(T)*n); }

template<typename T> inline bool same_mem(const T* p1, const T* p2, u32bit n)
   {
   bool is_same = true;

   for(u32bit i = 0; i != n; ++i)
      is_same &= (p1[i] == p2[i]);

   return is_same;
   }

}

#endif
