/**
* Internal-use debugging functions for Botan
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DEBUG_H__
#define BOTAN_DEBUG_H__

#include <botan/secmem.h>
#include <cstdio>

namespace Botan {

namespace Debug {

inline void print_vec(const std::string& name,
                      const byte array[], size_t array_len)
   {
   std::printf("%s = ", name.c_str());
   for(size_t i = 0; i != array_len; ++i)
      std::printf("%02X", array[i]);
   std::printf("\n");
   }

inline void print_vec(const std::string& name,
                      const MemoryRegion<byte>& vec)
   {
   print_vec(name, &vec[0], vec.size());
   }

}

}

#endif
