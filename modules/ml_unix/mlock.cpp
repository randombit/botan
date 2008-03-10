/*************************************************
* Memory Locking Functions Source File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/util.h>

#ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 199309
#endif

#include <sys/types.h>
#include <sys/mman.h>

namespace Botan {

/*************************************************
* Lock an area of memory into RAM                *
*************************************************/
void lock_mem(void* ptr, u32bit bytes)
   {
   mlock(ptr, bytes);
   }

/*************************************************
* Unlock a previously locked region of memory    *
*************************************************/
void unlock_mem(void* ptr, u32bit bytes)
   {
   munlock(ptr, bytes);
   }

}
