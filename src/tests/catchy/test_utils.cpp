/*
(C) 2015 Simon Warta (Kullo GmbH)
(C) 2015 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
*/

#include "catchy_tests.h"

#include <botan/parsing.h>

using namespace Botan;

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
