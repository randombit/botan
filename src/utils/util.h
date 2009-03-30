/*
* Utility Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_UTIL_H__
#define BOTAN_UTIL_H__

#include <botan/types.h>

namespace Botan {

/*
* Time Access Functions
*/
BOTAN_DLL u64bit system_time();

/*
* Memory Locking Functions
*/
BOTAN_DLL bool lock_mem(void*, u32bit);
BOTAN_DLL void unlock_mem(void*, u32bit);

/*
* Misc Utility Functions
*/
BOTAN_DLL u32bit round_up(u32bit, u32bit);
BOTAN_DLL u32bit round_down(u32bit, u32bit);

/*
* Work Factor Estimates
*/
BOTAN_DLL u32bit dl_work_factor(u32bit);

}

#endif
