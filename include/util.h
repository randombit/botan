/*************************************************
* Utility Functions Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_UTIL_H__
#define BOTAN_UTIL_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* Timer Access Functions                         *
*************************************************/
u64bit system_time();
u64bit system_clock();

/*************************************************
* Memory Locking Functions                       *
*************************************************/
void lock_mem(void*, u32bit);
void unlock_mem(void*, u32bit);

/*************************************************
* Misc Utility Functions                         *
*************************************************/
u32bit round_up(u32bit, u32bit);
u32bit round_down(u32bit, u32bit);
u64bit combine_timers(u32bit, u32bit, u32bit);

/*************************************************
* Work Factor Estimates                          *
*************************************************/
u32bit entropy_estimate(const byte[], u32bit);
u32bit dl_work_factor(u32bit);

}

#endif
