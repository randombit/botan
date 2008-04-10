/*************************************************
* Timestamp Functions Source File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/timers.h>
#include <botan/libstate.h>
#include <ctime>

namespace Botan {

/*************************************************
* Timer Access Functions                         *
*************************************************/
u64bit system_time()
   {
   return static_cast<u64bit>(std::time(0));
   }

u64bit system_clock()
   {
   return global_state().system_clock();
   }

/*************************************************
* Default Timer clock reading                    *
*************************************************/
u64bit Timer::clock() const
   {
   return combine_timers(std::time(0), std::clock(), CLOCKS_PER_SEC);
   }

/*************************************************
* Combine a two time values into a single one    *
*************************************************/
u64bit Timer::combine_timers(u32bit seconds, u32bit parts, u32bit parts_hz)
   {
   const u64bit NANOSECONDS_UNITS = 1000000000;
   parts *= (NANOSECONDS_UNITS / parts_hz);
   return ((seconds * NANOSECONDS_UNITS) + parts);
   }

}
