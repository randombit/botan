#include "timer.h"
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

std::ostream& operator<<(std::ostream& out, Timer& timer)
   {
   //out << timer.value() << " ";

   int events_per_second = timer.events() / timer.seconds();

   out << events_per_second << " " << timer.get_name() << " per second; ";

   if(timer.seconds_per_event() < 1)
      out << std::setprecision(2) << std::fixed
          << timer.ms_per_event() << " ms/" << timer.get_name();
   else
      out << std::setprecision(4) << std::fixed
          << timer.seconds_per_event() << " s/" << timer.get_name();

   if(timer.seconds() > 3)
      out << " (" << timer.events() << " ops in "
          << timer.milliseconds() << " ms)";
   else
      out << " (" << timer.events() << " ops in "
          << timer.seconds() << " s)";

   return out;
   }
