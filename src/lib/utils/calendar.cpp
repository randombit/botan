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
#include <array>

namespace Botan {

namespace {

/*
Portable replacement for timegm, _mkgmtime, etc

Algorithm due to Howard Hinnant

See https://howardhinnant.github.io/date_algorithms.html#days_from_civil
for details and explanation. The code is slightly simplified by our assumption
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

/*
Portable replacement for gmtime, gmtime_r, _gmtime_s, etc

Algorithm due to Howard Hinnant

See https://howardhinnant.github.io/date_algorithms.html#civil_from_days
for details and explanation.
*/
std::array<uint32_t, 6> civil_from_time_point(const std::chrono::system_clock::time_point& tp) {
   const int64_t t = static_cast<int64_t>(std::chrono::system_clock::to_time_t(tp));

   // Split into days since epoch and seconds within the day, flooring towards
   // negative infinity so that times before the epoch are handled correctly.
   int64_t days = t / 86400;
   int64_t tod = t % 86400;
   if(tod < 0) {
      tod += 86400;
      days -= 1;
   }

   const int64_t z = days + 719468;
   const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
   const int64_t doe = z - era * 146097;                                       // [0, 146096]
   const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;  // [0, 399]
   const int64_t y = yoe + era * 400;
   const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);  // [0, 365]
   const int64_t mp = (5 * doy + 2) / 153;                       // [0, 11]
   const int64_t day = doy - (153 * mp + 2) / 5 + 1;             // [1, 31]
   const int64_t month = mp < 10 ? mp + 3 : mp - 9;              // [1, 12]
   const int64_t year = y + (month <= 2 ? 1 : 0);

   return {static_cast<uint32_t>(year),
           static_cast<uint32_t>(month),
           static_cast<uint32_t>(day),
           static_cast<uint32_t>(tod / 3600),
           static_cast<uint32_t>((tod % 3600) / 60),
           static_cast<uint32_t>(tod % 60)};
}

}  // namespace

calendar_point::calendar_point(uint32_t y, uint32_t mon, uint32_t d, uint32_t h, uint32_t min, uint32_t sec) :
      m_year(static_cast<uint16_t>(y)),
      m_month(static_cast<uint8_t>(mon)),
      m_day(static_cast<uint8_t>(d)),
      m_hour(static_cast<uint8_t>(h)),
      m_minutes(static_cast<uint8_t>(min)),
      m_seconds(static_cast<uint8_t>(sec)) {
   BOTAN_ARG_CHECK(y <= 9999, "Year is outside representable range");
   BOTAN_ARG_CHECK(mon >= 1 && mon <= 12, "Month is outside range");
   BOTAN_ARG_CHECK(d >= 1 && d <= 31, "Day is outside range");
   BOTAN_ARG_CHECK(h < 24, "Hour is outside range");
   BOTAN_ARG_CHECK(min < 60, "Minute is outside range");
   BOTAN_ARG_CHECK(sec < 60, "Seconds is outside range");
}

uint64_t calendar_point::seconds_since_epoch() const {
   return (days_since_epoch(year(), month(), day()) * 86400) + (hour() * 60 * 60) + (minutes() * 60) + seconds();
}

std::chrono::system_clock::time_point calendar_point::to_std_timepoint() const {
   const uint64_t seconds_64 = this->seconds_since_epoch();

   /*
   * The tick of a system_clock varies by implementation, and so also the
   * largest representable value varies. Ensure this date is within range of the
   * clock implementation.
   */
   constexpr uint64_t max_representable_seconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::duration::max()).count());

   if(seconds_64 > max_representable_seconds) {
      throw Invalid_Argument("calendar_point::to_std_timepoint time is outside the representable range");
   }

   const time_t seconds_time_t = static_cast<time_t>(seconds_64);

   if(seconds_64 - seconds_time_t != 0) {
      throw Invalid_Argument("calendar_point::to_std_timepoint time_t overflow");
   }

   return std::chrono::system_clock::from_time_t(seconds_time_t);
}

calendar_point::calendar_point(const std::chrono::system_clock::time_point& time_point) {
   const auto [year, month, day, hour, minute, second] = civil_from_time_point(time_point);

   BOTAN_ARG_CHECK(year <= 9999, "Year is outside representable range");

   m_year = static_cast<uint16_t>(year);
   m_month = static_cast<uint8_t>(month);
   m_day = static_cast<uint8_t>(day);
   m_hour = static_cast<uint8_t>(hour);
   m_minutes = static_cast<uint8_t>(minute);
   m_seconds = static_cast<uint8_t>(second);
}

}  // namespace Botan
