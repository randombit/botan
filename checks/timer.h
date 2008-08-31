
#ifndef BOTAN_BENCHMARK_TIMER_H__
#define BOTAN_BENCHMARK_TIMER_H__

#include <botan/types.h>
#include <ostream>
#include <string>

using Botan::u64bit;
using Botan::u32bit;

class Timer
   {
   public:
      static u64bit get_clock();

      Timer(const std::string& name);

      void start();

      void stop();

      u64bit value();
      double seconds();
      double milliseconds();

      double ms_per_event();
      double seconds_per_event();

      u32bit events() const { return event_count; }
      std::string get_name() const { return name; }
   private:
      std::string name;
      u64bit time_used, timer_start;
      u32bit event_count;
   };

inline bool operator<(const Timer& x, const Timer& y)
   {
   return (x.get_name() < y.get_name());
   }

inline bool operator==(const Timer& x, const Timer& y)
   {
   return (x.get_name() == y.get_name());
   }

std::ostream& operator<<(std::ostream&, Timer&);

#endif
