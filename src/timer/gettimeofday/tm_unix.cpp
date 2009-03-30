/*
* Unix Timer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/tm_unix.h>
#include <botan/util.h>
#include <sys/time.h>

namespace Botan {

/*
* Get the timestamp
*/
u64bit Unix_Timer::clock() const
   {
   struct ::timeval tv;
   ::gettimeofday(&tv, 0);
   return combine_timers(tv.tv_sec, tv.tv_usec, 1000000);
   }

}
