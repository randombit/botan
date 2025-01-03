/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "timer.h"

#include <chrono>
#include <iomanip>
#include <sstream>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan_CLI {

namespace {

std::string format_timer_name(std::string_view name, std::string_view provider) {
   if(provider.empty() || provider == "base") {
      return std::string(name);
   }

   std::ostringstream out;
   out << name << " [" << provider << "]";
   return out.str();
}

}  // namespace

Timer::Timer(std::string_view name,
             std::string_view provider,
             std::string_view doing,
             uint64_t event_mult,
             size_t buf_size,
             double clock_cycle_ratio,
             uint64_t clock_speed) :
      m_name(format_timer_name(name, provider)),
      m_doing(doing),
      m_buf_size(buf_size),
      m_event_mult(event_mult),
      m_clock_cycle_ratio(clock_cycle_ratio),
      m_clock_speed(clock_speed) {}

void Timer::start() {
   stop();
   m_timer_start = timestamp_ns();
   m_cpu_cycles_start = cycle_counter();
}

uint64_t Timer::timestamp_ns() {
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

uint64_t Timer::cycle_counter() {
#if defined(BOTAN_HAS_OS_UTILS)
   return Botan::OS::get_cpu_cycle_counter();
#else
   return 0;
#endif
}

void Timer::stop() {
   if(m_timer_start) {
      const uint64_t now = timestamp_ns();

      if(now > m_timer_start) {
         m_time_used += (now - m_timer_start);
      }

      if(m_cpu_cycles_start != 0) {
         const uint64_t cycles_taken = cycle_counter() - m_cpu_cycles_start;
         if(cycles_taken > 0) {
            m_cpu_cycles_used += static_cast<size_t>(cycles_taken * m_clock_cycle_ratio);
         }
      }

      m_timer_start = 0;
      ++m_event_count;
   }
}

bool Timer::operator<(const Timer& other) const {
   if(this->doing() != other.doing()) {
      return (this->doing() < other.doing());
   }

   return (this->get_name() < other.get_name());
}

}  // namespace Botan_CLI
