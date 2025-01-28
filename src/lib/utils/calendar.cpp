/*
* Calendar Functions
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/calendar.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace Botan {

namespace {

std::tm do_gmtime(std::time_t time_val) {
   std::tm tm;

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   ::gmtime_s(&tm, &time_val);  // Windows
#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::gmtime_r(&time_val, &tm);  // Unix/SUSv2
#else
   std::tm* tm_p = std::gmtime(&time_val);
   if(tm_p == nullptr)
      throw Encoding_Error("time_t_to_tm could not convert");
   tm = *tm_p;
#endif

   return tm;
}

/*
Portable replacement for timegm, _mkgmtime, etc

Algorithm due to Howard Hinnant

See https://howardhinnant.github.io/date_algorithms.html#days_from_civil
for details and explaination. The code is slightly simplified by our assumption
that the date is at least 1970, which is sufficient for our purposes.
*/
uint64_t days_since_epoch(uint32_t year, uint32_t month, uint32_t day) {
   BOTAN_ARG_CHECK(year >= 1970, "Years before 1970 not supported");

   if(month <= 2) {
      year -= 1;
   }
   const uint32_t era = year / 400;
   const uint32_t yoe = year - era * 400;                                          // [0, 399]
   const uint32_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;  // [0, 365]
   const uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                     // [0, 146096]
   return era * 146097 + doe - 719468;
}

}  // namespace

uint64_t calendar_point::seconds_since_epoch() const {
   return (days_since_epoch(year(), month(), day()) * 86400) + (hour() * 60 * 60) + (minutes() * 60) + seconds();
}

std::chrono::system_clock::time_point calendar_point::to_std_timepoint() const {
   const uint64_t seconds_64 = this->seconds_since_epoch();
   const time_t seconds_time_t = static_cast<time_t>(seconds_64);

   if(seconds_64 - seconds_time_t != 0) {
      throw Invalid_Argument("calendar_point::to_std_timepoint time_t overflow");
   }

   return std::chrono::system_clock::from_time_t(seconds_time_t);
}

std::string calendar_point::to_string() const {
   // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
   std::stringstream output;
   output << std::setfill('0') << std::setw(4) << year() << "-" << std::setw(2) << month() << "-" << std::setw(2)
          << day() << "T" << std::setw(2) << hour() << ":" << std::setw(2) << minutes() << ":" << std::setw(2)
          << seconds();
   return output.str();
}

calendar_point::calendar_point(const std::chrono::system_clock::time_point& time_point) {
   std::tm tm = do_gmtime(std::chrono::system_clock::to_time_t(time_point));

   m_year = tm.tm_year + 1900;
   m_month = tm.tm_mon + 1;
   m_day = tm.tm_mday;
   m_hour = tm.tm_hour;
   m_minutes = tm.tm_min;
   m_seconds = tm.tm_sec;
}

}  // namespace Botan
