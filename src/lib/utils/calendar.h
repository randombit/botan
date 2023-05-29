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
#include <string>

namespace Botan {

/**
* Struct representing a particular date and time
*/
class BOTAN_TEST_API calendar_point {
   public:
      /** The year */
      uint32_t year() const { return m_year; }

      /** The month, 1 through 12 for Jan to Dec */
      uint32_t month() const { return m_month; }

      /** The day of the month, 1 through 31 (or 28 or 30 based on month */
      uint32_t day() const { return m_day; }

      /** Hour in 24-hour form, 0 to 23 */
      uint32_t hour() const { return m_hour; }

      /** Minutes in the hour, 0 to 60 */
      uint32_t minutes() const { return m_minutes; }

      /** Seconds in the minute, 0 to 60, but might be slightly
      larger to deal with leap seconds on some systems
      */
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
      calendar_point(uint32_t y, uint32_t mon, uint32_t d, uint32_t h, uint32_t min, uint32_t sec) :
            m_year(y), m_month(mon), m_day(d), m_hour(h), m_minutes(min), m_seconds(sec) {}

      /**
      * Convert a time_point to a calendar_point
      * @param time_point a time point from the system clock
      */
      calendar_point(const std::chrono::system_clock::time_point& time_point);

      /**
      * Returns an STL timepoint object
      */
      std::chrono::system_clock::time_point to_std_timepoint() const;

      /**
      * Returns a human readable string of the struct's components.
      * Formatting might change over time. Currently it is RFC339 'iso-date-time'.
      */
      std::string to_string() const;

   private:
      uint32_t m_year;
      uint32_t m_month;
      uint32_t m_day;
      uint32_t m_hour;
      uint32_t m_minutes;
      uint32_t m_seconds;
};

}  // namespace Botan

#endif
