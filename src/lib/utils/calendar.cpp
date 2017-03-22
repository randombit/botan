/*
* Calendar Functions
* (C) 1999-2010 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/calendar.h>
#include <botan/exceptn.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <botan/mutex.h>
#include <stdlib.h>

#if defined(BOTAN_HAS_BOOST_DATETIME)
#include <boost/date_time/posix_time/posix_time_types.hpp>
#endif

namespace Botan {

namespace {

std::tm do_gmtime(std::time_t time_val)
   {
   std::tm tm;

#if defined(BOTAN_TARGET_OS_HAS_GMTIME_S)
   gmtime_s(&tm, &time_val); // Windows
#elif defined(BOTAN_TARGET_OS_HAS_GMTIME_R)
   gmtime_r(&time_val, &tm); // Unix/SUSv2
#else
   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == nullptr)
      throw Encoding_Error("time_t_to_tm could not convert");
   tm = *tm_p;
#endif

   return tm;
   }

#if !defined(BOTAN_TARGET_OS_HAS_TIMEGM) && !(defined(BOTAN_TARGET_OS_HAS_MKGMTIME) && defined(BOTAN_BUILD_COMPILER_IS_MSVC))

#if defined(BOTAN_HAS_BOOST_DATETIME)

std::time_t boost_timegm(std::tm *tm)
   {
   const int sec  = tm->tm_sec;
   const int min  = tm->tm_min;
   const int hour = tm->tm_hour;
   const int day  = tm->tm_mday;
   const int mon  = tm->tm_mon + 1;
   const int year = tm->tm_year + 1900;

   std::time_t out;

      {
      using namespace boost::posix_time;
      using namespace boost::gregorian;
      const auto epoch = ptime(date(1970, 01, 01));
      const auto time = ptime(date(year, mon, day),
                              hours(hour) + minutes(min) + seconds(sec));
      const time_duration diff(time - epoch);
      out = diff.ticks() / diff.ticks_per_second();
      }

   return out;
   }

#elif defined(BOTAN_OS_TYPE_IS_UNIX)

#pragma message "Caution! A fallback version of timegm() is used which is not thread-safe"

mutex_type ENV_TZ;

std::time_t fallback_timegm(std::tm *tm)
   {
   std::time_t out;
   std::string tz_backup;

   ENV_TZ.lock();

   // Store current value of env variable TZ
   const char* tz_env_pointer = ::getenv("TZ");
   if (tz_env_pointer != nullptr)
      tz_backup = std::string(tz_env_pointer);

   // Clear value of TZ
   ::setenv("TZ", "", 1);
   ::tzset();

   out = ::mktime(tm);

   // Restore TZ
   if (!tz_backup.empty())
      {
      // setenv makes a copy of the second argument
      ::setenv("TZ", tz_backup.data(), 1);
      }
   else
      {
      ::unsetenv("TZ");
      }
   ::tzset();

   ENV_TZ.unlock();

   return out;
}
#endif // BOTAN_HAS_BOOST_DATETIME

#endif

}

std::chrono::system_clock::time_point calendar_point::to_std_timepoint() const
   {
   if (year < 1970)
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years before 1970.");

   // 32 bit time_t ends at January 19, 2038
   // https://msdn.microsoft.com/en-us/library/2093ets1.aspx
   // Throw after 2037 if 32 bit time_t is used
   if (year > 2037 && sizeof(std::time_t) == 4)
      {
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2037.");
      }

   // std::tm: struct without any timezone information
   std::tm tm;
   tm.tm_isdst = -1; // i.e. no DST information available
   tm.tm_sec   = seconds;
   tm.tm_min   = minutes;
   tm.tm_hour  = hour;
   tm.tm_mday  = day;
   tm.tm_mon   = month - 1;
   tm.tm_year  = year - 1900;

   // Define a function alias `botan_timegm`
   #if defined(BOTAN_TARGET_OS_HAS_TIMEGM)
   std::time_t (&botan_timegm)(std::tm *tm) = timegm;
   #elif defined(BOTAN_TARGET_OS_HAS_MKGMTIME) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   // http://stackoverflow.com/questions/16647819/timegm-cross-platform
   std::time_t (&botan_timegm)(std::tm *tm) = _mkgmtime;
   #elif defined(BOTAN_HAS_BOOST_DATETIME)
   std::time_t (&botan_timegm)(std::tm *tm) = boost_timegm;
   #elif defined(BOTAN_OS_TYPE_IS_UNIX)
   std::time_t (&botan_timegm)(std::tm *tm) = fallback_timegm;
   #else
   std::time_t (&botan_timegm)(std::tm *tm) = mktime; // localtime instead...
   #endif

   // Convert std::tm to std::time_t
   std::time_t tt = botan_timegm(&tm);
   if (tt == -1)
      throw Invalid_Argument("calendar_point couldn't be converted: " + to_string());

   return std::chrono::system_clock::from_time_t(tt);
   }

std::string calendar_point::to_string() const
   {
   // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
   std::stringstream output;
      {
      using namespace std;
      output << setfill('0')
             << setw(4) << year << "-" << setw(2) << month << "-" << setw(2) << day
             << "T"
             << setw(2) << hour << ":" << setw(2) << minutes << ":" << setw(2) << seconds;
      }
   return output.str();
   }


calendar_point calendar_value(
   const std::chrono::system_clock::time_point& time_point)
   {
   std::tm tm = do_gmtime(std::chrono::system_clock::to_time_t(time_point));

   return calendar_point(tm.tm_year + 1900,
                         tm.tm_mon + 1,
                         tm.tm_mday,
                         tm.tm_hour,
                         tm.tm_min,
                         tm.tm_sec);
   }

}
