/*
* OS specific utility functions
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OS_UTILS_H__
#define BOTAN_OS_UTILS_H__

#include <botan/types.h>

namespace Botan {

namespace OS {

/**
* Returns the OS assigned process ID, if available. Otherwise throws.
*/
uint32_t get_process_id();

/**
* Returns the value of the hardware cycle counter, if available.
* Returns 0 if not available. On Windows uses QueryPerformanceCounter.
* On other platforms reads the native cycle counter directly.
* The epoch and update rate are arbitrary and may not be constant
* (depending on the hardware).
*/
uint64_t get_processor_timestamp();

/**
* Returns the value of the system clock with best resolution available,
* normalized to nanoseconds resolution.
*/
uint64_t get_system_timestamp_ns();

/*
* Returns the maximum amount of memory (in bytes) we could/should
* hyptothetically allocate. Reads "BOTAN_MLOCK_POOL_SIZE" from
* environment which can be set to zero.
*/
size_t get_memory_locking_limit();

/*
* Request so many bytes of page-aligned RAM locked into memory using
* mlock, VirtualLock, or similar. Returns null on failure. The memory
* returned is zeroed. Free it with free_locked_pages.
*/
void* allocate_locked_pages(size_t length);

/*
* Free memory allocated by allocate_locked_pages
*/
void free_locked_pages(void* ptr, size_t length);

}

}

#endif
