/*
* Calendar Functions
* (C) 1999-2009,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CALENDAR_H_
#define BOTAN_CALENDAR_H_

#include <botan/types.h>
#include <chrono>

namespace Botan {

/**
* Struct representing a particular date and time
*/
class BOTAN_TEST_API calendar_point final {
   public:
      /** The year, less than or equal to 9999 */
      uint32_t year() const { return m_year; }

      /** The month, 1 through 12 for Jan to Dec */
      uint32_t month() const { return m_month; }

      /** The day of the month, 1 through 31 */
      uint32_t day() const { return m_day; }

      /** Hour in 24-hour form, 0 to 23 */
      uint32_t hour() const { return m_hour; }

      /** Minutes in the hour, 0 to 59 */
      uint32_t minutes() const { return m_minutes; }

      /** Seconds in the minute, 0 to 59 */
      uint32_t seconds() const { return m_seconds; }

      /**
      * Initialize a calendar_point
      * @param y the year
      * @param mon the month
      * @param d the day
      * @param h the hour
      * @param min the minute
      * @param sec the second
      */
      calendar_point(uint32_t y, uint32_t mon, uint32_t d, uint32_t h, uint32_t min, uint32_t sec);

      /**
      * Convert a time_point to a calendar_point
      * @param time_point a time point from the system clock
      */
      explicit calendar_point(const std::chrono::system_clock::time_point& time_point);

      /**
      * Return seconds since epoch
      */
      uint64_t seconds_since_epoch() const;

      /**
      * Returns an STL timepoint object
      *
      * Note this throws an exception if the time is not representable
      * in the system time_t
      */
      std::chrono::system_clock::time_point to_std_timepoint() const;

   private:
      uint16_t m_year;
      uint8_t m_month;
      uint8_t m_day;
      uint8_t m_hour;
      uint8_t m_minutes;
      uint8_t m_seconds;
};

}  // namespace Botan

#endif
