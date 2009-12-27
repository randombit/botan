/**
* Internal-use debugging functions for Botan
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DEBUG_H__
#define BOTAN_DEBUG_H__

#include <botan/secmem.h>

namespace Botan {

namespace Debug {

void print_vec(const std::string& name,
               const byte array[],
               size_t array_len);

void print_vec(const std::string& name,
               const MemoryRegion<byte>& vec);


}

}

#endif
