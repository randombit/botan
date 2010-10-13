/*
* Memory Locking Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MLOCK_H__
#define BOTAN_MLOCK_H__

#include <botan/types.h>

namespace Botan {

/**
* Check if we can at least potentially lock memory
*/
bool has_mlock();

/**
* Lock memory into RAM if possible
* @param addr the start of the memory block
* @param length the length of the memory block in bytes
* @returns true if successful, false otherwise
*/
bool lock_mem(void* addr, size_t length);

/**
* Unlock memory locked with lock_mem()
* @param addr the start of the memory block
* @param length the length of the memory block in bytes
*/
void unlock_mem(void* addr, size_t length);

}

#endif
