/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "timer.h"
#include <botan/time.h>
#include <iomanip>

Timer::Timer(const std::string& n, u32bit e_mul) :
   name(n), event_mult(e_mul)
   {
   time_used = 0;
   timer_start = 0;
   event_count = 0;
   }

void Timer::start()
   {
   stop();
   timer_start = get_clock();
   }

void Timer::stop()
   {
   if(timer_start)
      {
      u64bit now = get_clock();

      if(now > timer_start)
         time_used += (now - timer_start);

      timer_start = 0;
      ++event_count;
      }
   }

u64bit Timer::get_clock()
   {
   return Botan::get_nanoseconds_clock();
   }

std::ostream& operator<<(std::ostream& out, Timer& timer)
   {
   //out << timer.value() << " ";

   double events_per_second_fl =
      static_cast<double>(timer.events() / timer.seconds());

   u64bit events_per_second = static_cast<u64bit>(events_per_second_fl);

   out << events_per_second << " " << timer.get_name() << " per second; ";

   std::string op_or_ops = (timer.events() == 1) ? "op" : "ops";

   out << std::setprecision(2) << std::fixed
       << timer.ms_per_event() << " ms/op"
       << " (" << timer.events() << " " << op_or_ops << " in "
       << timer.milliseconds() << " ms)";

   return out;
   }
