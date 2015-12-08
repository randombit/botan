/*
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

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

      Timer(const std::string& name, u32bit event_mult = 1) :
         m_name(name), m_event_mult(event_mult) {}

      void start();
      void stop();

      u64bit value() { stop(); return m_time_used; }
      double seconds() { return milliseconds() / 1000.0; }
      double milliseconds() { return value() / 1000000.0; }

      double ms_per_event() { return milliseconds() / events(); }
      double seconds_per_event() { return seconds() / events(); }

      u64bit events() const { return m_event_count * m_event_mult; }
      std::string get_name() const { return m_name; }
   private:
      std::string m_name;
      u64bit m_time_used = 0, m_timer_start = 0;
      u64bit m_event_count = 0, m_event_mult = 0;
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
