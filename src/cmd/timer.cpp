/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "timer.h"
#include <chrono>
#include <iomanip>

void Timer::start()
   {
   stop();
   m_timer_start = get_clock();
   }

void Timer::stop()
   {
   if(m_timer_start)
      {
      const u64bit now = get_clock();

      if(now > m_timer_start)
         m_time_used += (now - m_timer_start);

      m_timer_start = 0;
      ++m_event_count;
      }
   }

u64bit Timer::get_clock()
   {
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

std::ostream& operator<<(std::ostream& out, Timer& timer)
   {
   //out << timer.value() << " ";

   double events_per_second_fl =
      static_cast<double>(timer.events() / timer.seconds());

   u64bit events_per_second = static_cast<u64bit>(events_per_second_fl);

   out << events_per_second << " " << timer.get_name() << " per second; ";

   std::string op_or_ops = (timer.events() == 1) ? "op" : "ops";

   const std::ios::fmtflags flags = out.flags();

   out << std::setprecision(2) << std::fixed
       << timer.ms_per_event() << " ms/op"
       << " (" << timer.events() << " " << op_or_ops << " in "
       << timer.milliseconds() << " ms)";

   out.flags(flags);

   return out;
   }
