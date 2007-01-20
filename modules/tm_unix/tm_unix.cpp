/*************************************************
* Unix Timer Source File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/tm_unix.h>
#include <botan/util.h>
#include <sys/time.h>

namespace Botan {

/*************************************************
* Get the timestamp                              *
*************************************************/
u64bit Unix_Timer::clock() const
   {
   struct timeval tv;
   gettimeofday(&tv, 0);
   return combine_timers(tv.tv_sec, tv.tv_usec, 1000000);
   }

}
