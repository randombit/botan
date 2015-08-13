// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"

#include <botan/calendar.h>
#include <botan/parsing.h>
#include <botan/internal/rounding.h>

using namespace Botan;

TEST_CASE("round_up strictly positive", "[utils]")
   {
   CHECK_THAT(round_up( 1, 10), Equals(10));
   CHECK_THAT(round_up( 3, 10), Equals(10));
   CHECK_THAT(round_up( 9, 10), Equals(10));
   CHECK_THAT(round_up(10, 10), Equals(10));

   CHECK_THAT(round_up( 1, 4), Equals( 4));
   CHECK_THAT(round_up( 3, 4), Equals( 4));
   CHECK_THAT(round_up( 4, 4), Equals( 4));
   CHECK_THAT(round_up( 9, 4), Equals(12));
   CHECK_THAT(round_up(10, 4), Equals(12));
   }

TEST_CASE("round_up zero", "[utils]")
   {
   CHECK_THAT(round_up(0, 2),       Equals(0));
   CHECK_THAT(round_up(0, 10),      Equals(0));
   CHECK_THAT(round_up(0, 1000),    Equals(0));
   CHECK_THAT(round_up(0, 99999),   Equals(0));
   CHECK_THAT(round_up(0, 2222222), Equals(0));
   }

TEST_CASE("round_up invalid input", "[utils]")
   {
   CHECK_THROWS(round_up(3, 0));
   CHECK_THROWS(round_up(5, 0));
   }

TEST_CASE("calendar_point constructor works", "[utils]")
   {
      {
      auto point1 = calendar_point(1988, 04, 23, 14, 37, 28);
      CHECK_THAT(point1.year,    Equals(1988));
      CHECK_THAT(point1.month,   Equals(4));
      CHECK_THAT(point1.day,     Equals(23));
      CHECK_THAT(point1.hour,    Equals(14));
      CHECK_THAT(point1.minutes, Equals(37));
      CHECK_THAT(point1.seconds, Equals(28));
      }

      {
      auto point2 = calendar_point(1800, 01, 01, 0, 0, 0);
      CHECK_THAT(point2.year,    Equals(1800));
      CHECK_THAT(point2.month,   Equals(1));
      CHECK_THAT(point2.day,     Equals(1));
      CHECK_THAT(point2.hour,    Equals(0));
      CHECK_THAT(point2.minutes, Equals(0));
      CHECK_THAT(point2.seconds, Equals(0));
      }

      {
      auto point = calendar_point(2037, 12, 31, 24, 59, 59);
      CHECK_THAT(point.year,    Equals(2037));
      CHECK_THAT(point.month,   Equals(12));
      CHECK_THAT(point.day,     Equals(31));
      CHECK_THAT(point.hour,    Equals(24));
      CHECK_THAT(point.minutes, Equals(59));
      CHECK_THAT(point.seconds, Equals(59));
      }

      {
      auto point = calendar_point(2100, 5, 1, 0, 0, 0);
      CHECK_THAT(point.year,    Equals(2100));
      CHECK_THAT(point.month,   Equals(5));
      CHECK_THAT(point.day,     Equals(1));
      CHECK_THAT(point.hour,    Equals(0));
      CHECK_THAT(point.minutes, Equals(0));
      CHECK_THAT(point.seconds, Equals(0));
      }
   }

TEST_CASE("calendar_point to stl timepoint and back", "[utils]")
   {
   SECTION("default test")
      {
      auto in = calendar_point(1988, 04, 23, 14, 37, 28);
      auto out = calendar_value(in.to_std_timepoint());
      CHECK_THAT(out.year,    Equals(1988));
      CHECK_THAT(out.month,   Equals(4));
      CHECK_THAT(out.day,     Equals(23));
      CHECK_THAT(out.hour,    Equals(14));
      CHECK_THAT(out.minutes, Equals(37));
      CHECK_THAT(out.seconds, Equals(28));
      }

   // _mkgmtime on Windows does not work for dates before 1970
   SECTION("first possible time point")
      {
      auto in = calendar_point(1970, 01, 01, 00, 00, 00);
      auto out = calendar_value(in.to_std_timepoint());
      CHECK_THAT(out.year,    Equals(1970));
      CHECK_THAT(out.month,   Equals(01));
      CHECK_THAT(out.day,     Equals(01));
      CHECK_THAT(out.hour,    Equals(00));
      CHECK_THAT(out.minutes, Equals(00));
      CHECK_THAT(out.seconds, Equals(00));
      }

   SECTION("latest possible time point")
      {
      auto in = calendar_point(2037, 12, 31, 23, 59, 59);
      auto out = calendar_value(in.to_std_timepoint());
      CHECK_THAT(out.year,    Equals(2037));
      CHECK_THAT(out.month,   Equals(12));
      CHECK_THAT(out.day,     Equals(31));
      CHECK_THAT(out.hour,    Equals(23));
      CHECK_THAT(out.minutes, Equals(59));
      CHECK_THAT(out.seconds, Equals(59));
      }

   SECTION("year too early")
      {
         {
         auto in = calendar_point(1800, 01, 01, 0, 0, 0);
         CHECK_THROWS(in.to_std_timepoint());
         }

         {
         auto in = calendar_point(1899, 12, 31, 23, 59, 59);
         CHECK_THROWS(in.to_std_timepoint());
         }

         {
         auto in = calendar_point(1969, 12, 31, 23, 59, 58); // time_t = -2
         CHECK_THROWS(in.to_std_timepoint());
         }

         {
         auto in = calendar_point(1969, 12, 31, 23, 59, 59); // time_t = -1
         CHECK_THROWS(in.to_std_timepoint());
         }
      }

   SECTION("year too late")
      {
      auto in = calendar_point(2038, 01, 01, 0, 0, 0);
      CHECK_THROWS(in.to_std_timepoint());
      }
   }

TEST_CASE("uint32 parsing valid", "[utils]")
   {
   CHECK_THAT(to_u32bit("0"), Equals(0));
   CHECK_THAT(to_u32bit("1"), Equals(1));
   CHECK_THAT(to_u32bit("2"), Equals(2));
   CHECK_THAT(to_u32bit("10"), Equals(10));
   CHECK_THAT(to_u32bit("100"), Equals(100));
   CHECK_THAT(to_u32bit("1000"), Equals(1000));
   CHECK_THAT(to_u32bit("10000"), Equals(10000));
   CHECK_THAT(to_u32bit("100000"), Equals(100000));
   CHECK_THAT(to_u32bit("1000000"), Equals(1000000));
   // biggest allowed value
   CHECK_THAT(to_u32bit("4294967295"), Equals(4294967295));

   // leading zeros
   CHECK_THAT(to_u32bit("00"), Equals(0));
   CHECK_THAT(to_u32bit("01"), Equals(1));
   CHECK_THAT(to_u32bit("02"), Equals(2));
   CHECK_THAT(to_u32bit("010"), Equals(10));
   CHECK_THAT(to_u32bit("0000000000000000000000000010"), Equals(10));

   // leading and trailing whitespace
   CHECK_THROWS(to_u32bit(" 1"));
   CHECK_THROWS(to_u32bit(" 1 "));
   CHECK_THROWS(to_u32bit("\n1"));
   CHECK_THROWS(to_u32bit("1\n"));
   CHECK_THROWS(to_u32bit("1 5"));
   CHECK_THROWS(to_u32bit("1\t5"));
   CHECK_THROWS(to_u32bit("1\n5"));

   // Other stuff that is no digit
   CHECK_THROWS(to_u32bit("1Z"));

   // invalid input
   CHECK_THROWS(to_u32bit(""));
   CHECK_THROWS(to_u32bit(" "));
   CHECK_THROWS(to_u32bit("!"));
   //CHECK_THROWS(to_u32bit("1!"));
   CHECK_THROWS(to_u32bit("!1"));

   // Avoid overflow: value too big for uint32
   CHECK_THROWS(to_u32bit("4294967296"));
   }
