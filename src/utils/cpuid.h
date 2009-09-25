/**
* Runtime CPU detection
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CPUID_H__
#define BOTAN_CPUID_H__

#include <botan/types.h>

namespace Botan {

namespace CPUID {

/**
* Return a best guess of the cache line size
*/
u32bit cache_line_size();

/**
* Check if the processor supports RDTSC
*/
bool has_rdtsc();

/**
* Check if the processor supports SSE2
*/
bool has_sse2();

/**
* Check if the processor supports SSSE3
*/
bool has_ssse3();

/**
* Check if the processor supports SSE4.1
*/
bool has_sse41();

/**
* Check if the processor supports SSE4.2
*/
bool has_sse42();

}

}

#endif
