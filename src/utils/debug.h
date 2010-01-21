/**
* Internal-use debugging functions for Botan
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DEBUG_H__
#define BOTAN_DEBUG_H__

#include <botan/secmem.h>
#include <iostream>

namespace Botan {

namespace Debug {

template<typename T>
void print_vec(const std::string& name,
               const T array[], size_t array_len)
   {
   std::cout << name << " = ";

   for(size_t i = 0; i != array_len; ++i)
      std::cout << std::hex << array[i];
   std::cout << std::endl;
   }

template<typename T>
void print_vec(const std::string& name,
               const MemoryRegion<T>& vec)
   {
   print_vec(name, &vec[0], vec.size());
   }

}

}

#endif
