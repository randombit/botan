#include "timer.h"
#include <time.h>
#include <iomanip>

u64bit Timer::get_clock()
   {
   struct timespec tv;
   clock_gettime(CLOCK_REALTIME, &tv);
   return (tv.tv_sec * 1000000000ULL + tv.tv_nsec);
   }

Timer::Timer(const std::string& n) : name(n)
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

u64bit Timer::value()
   {
   stop();
   return time_used;
   }

double Timer::seconds()
   {
   return milliseconds() / 1000.0;
   }

double Timer::milliseconds()
   {
   return value() / 1000000.0;
   }

double Timer::ms_per_event()
   {
   return milliseconds() / events();
   }

double Timer::seconds_per_event()
   {
   return seconds() / events();
   }

std::ostream& operator<<(std::ostream& out, Timer& timer)
   {
   //out << timer.value() << " ";

   int events_per_second = timer.events() / timer.seconds();

   out << events_per_second << " " << timer.get_name() << " per second; ";

   if(timer.seconds_per_event() < 10)
      out << std::setprecision(2) << std::fixed
          << timer.ms_per_event() << " ms/" << timer.get_name();
   else
      out << std::setprecision(4) << std::fixed
          << timer.seconds_per_event() << " s/" << timer.get_name();

   if(timer.seconds() < 10)
      out << " (" << timer.events() << " ops in "
          << timer.milliseconds() << " ms)";
   else
      out << " (" << timer.events() << " ops in "
          << timer.seconds() << " s)";

   return out;
   }
