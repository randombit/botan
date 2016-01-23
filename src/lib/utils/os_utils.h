/*
* OS specific utility functions
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OS_UTILS_H__
#define BOTAN_OS_UTILS_H__

#include <botan/types.h>

namespace Botan {

namespace OS {

/**
* Return the process ID, or 0 if not available
*/
uint32_t get_process_id();

/**
* Return the CPU cycle counter, if available on the current system.
* On Windows, uses QueryPerformanceCounter
* On other platforms, accesses the CPU counter directly
*
* Returns 0 if CPU timestamp is not available on this system
*/
//uint64_t get_cpu_timestamp();

/*
* Returns the maximum amount of memory (in bytes) we could/should
* hyptothetically allocate. Reads "BOTAN_MLOCK_POOL_SIZE" from
* environment which can be set to zero.
*/
size_t get_memory_locking_limit();

/*
* Request so many bytes of page-aligned RAM locked into memory OS
* calls (mlock, VirtualLock, or similar). Returns null on failure. The
* memory returned is zeroed. Free it with free_locked_pages.
*/
void* allocate_locked_pages(size_t length);

/*
* Free memory allocated by allocate_locked_pages
*/
void free_locked_pages(void* ptr, size_t length);

}

}

#endif
