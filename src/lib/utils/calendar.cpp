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

}

std::chrono::system_clock::time_point calendar_point::to_std_timepoint()
   {
   if (year < 1900)
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years before 1990.");

   // 32 bit time_t ends at January 19, 2038
   // https://msdn.microsoft.com/en-us/library/2093ets1.aspx
   // For consistency reasons, throw after 2037 as long as
   // no other implementation is available.
   if (year > 2037)
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2037.");

   std::tm tm;
   tm.tm_sec   = seconds;
   tm.tm_min   = minutes;
   tm.tm_hour  = hour;
   tm.tm_mday  = day;
   tm.tm_mon   = month - 1;
   tm.tm_year  = year - 1900;

   // Convert std::tm to std::time_t
   // http://stackoverflow.com/questions/16647819/timegm-cross-platform
   #if defined(BOTAN_TARGET_OS_IS_WINDOWS)
   #define timegm _mkgmtime
   #endif
   std::time_t tt = timegm(&tm);
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
