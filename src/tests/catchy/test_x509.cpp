// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"

#if defined(BOTAN_HAS_ASN1)

#include <botan/exceptn.h>
#include <botan/asn1_time.h>

using namespace Botan;
using namespace Catch;

TEST_CASE("human readable time", "[X509]")
   {
   auto time1 = X509_Time("0802010000Z", ASN1_Tag::UTC_TIME);
   auto time2 = X509_Time("0802011724Z", ASN1_Tag::UTC_TIME);
   auto time3 = X509_Time("040614233430Z", ASN1_Tag::UTC_TIME);

   CHECK_THAT(time1.time_is_set(), Equals(true));
   CHECK_THAT(time2.time_is_set(), Equals(true));
   CHECK_THAT(time3.time_is_set(), Equals(true));

   CHECK_THAT(time1.readable_string(), Equals("2008/02/01 00:00:00 UTC"));
   CHECK_THAT(time2.readable_string(), Equals("2008/02/01 17:24:00 UTC"));
   CHECK_THAT(time3.readable_string(), Equals("2004/06/14 23:34:30 UTC"));
   }

TEST_CASE("Implicit copy constructor", "[X509]")
   {
   auto time_orig = X509_Time("0802010000Z", ASN1_Tag::UTC_TIME);
   auto time_copy = time_orig;

   // Check that implicit copy and assignment work:
   // time_copy and time_orig must have the same data but
   // must sit at different places in memory
   CHECK((time_orig == time_copy));

   auto address1 = reinterpret_cast<uintptr_t>(&time_orig);
   auto address2 = reinterpret_cast<uintptr_t>(&time_copy);

   CHECK_THAT(address1, Not(Equals(address2)));
   }

TEST_CASE("no time", "[X509]")
   {
   auto time = X509_Time();
   CHECK_THAT(time.time_is_set(), Equals(false));
   }

TEST_CASE("valid UTCTime", "[X509]")
   {
    SECTION("precision: minute; including timezone: no", "Length 11")
       {
       CHECK_NOTHROW(X509_Time("0802010000Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("0802011724Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("0406142334Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("9906142334Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("0006142334Z", ASN1_Tag::UTC_TIME));
       }

    SECTION("precision: seconds; including timezone: no", "Length 13")
       {
       CHECK_NOTHROW(X509_Time("080201000000Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("080201172412Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("040614233433Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("990614233444Z", ASN1_Tag::UTC_TIME));
       CHECK_NOTHROW(X509_Time("000614233455Z", ASN1_Tag::UTC_TIME));
       }

    SECTION("precision: minute; including timezone: yes", "Length 15")
       {
       // Valid times that are not supported by Botan
       CHECK_THROWS_AS(X509_Time("0802010000-0000", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("0802011724+0000", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("0406142334-0500", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("9906142334+0500", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("0006142334-0530", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("0006142334+0530", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       }

    SECTION("precision: seconds; including timezone: yes", "Length 17")
       {
       // Valid times that are not supported by Botan
       CHECK_THROWS_AS(X509_Time("080201000000-0000", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("080201172412+0000", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("040614233433-0500", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("990614233444+0500", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("000614233455-0530", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       CHECK_THROWS_AS(X509_Time("000614233455+0530", ASN1_Tag::UTC_TIME), Unsupported_Argument);
       }
   }

TEST_CASE("invalid UTCTime", "[X509]")
   {
   // invalid length
   CHECK_THROWS(X509_Time("", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time(" ", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2008`02-01", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("9999-02-01", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2000-02-01 17", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("999921", ASN1_Tag::UTC_TIME));

   // valid length 13 -> range check
   CHECK_THROWS(X509_Time("080201000061Z", ASN1_Tag::UTC_TIME)); // seconds too big (61)
   CHECK_THROWS(X509_Time("080201000060Z", ASN1_Tag::UTC_TIME)); // seconds too big (60, leap seconds not covered by the standard)
   CHECK_THROWS(X509_Time("0802010000-1Z", ASN1_Tag::UTC_TIME)); // seconds too small (-1)
   CHECK_THROWS(X509_Time("080201006000Z", ASN1_Tag::UTC_TIME)); // minutes too big (60)
   CHECK_THROWS(X509_Time("080201240000Z", ASN1_Tag::UTC_TIME)); // hours too big (24:00)

   // valid length 13 -> invalid numbers
   CHECK_THROWS(X509_Time("08020123112 Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08020123112!Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08020123112,Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08020123112\nZ", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("080201232 33Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("080201232!33Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("080201232,33Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("080201232\n33Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("0802012 3344Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("0802012!3344Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("0802012,3344Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08022\n334455Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08022 334455Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08022!334455Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08022,334455Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("08022\n334455Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("082 33445511Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("082!33445511Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("082,33445511Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("082\n33445511Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2 2211221122Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2!2211221122Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2,2211221122Z", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2\n2211221122Z", ASN1_Tag::UTC_TIME));

   // wrong time zone
   CHECK_THROWS(X509_Time("0802010000", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("0802010000z", ASN1_Tag::UTC_TIME));
   }

#endif // BOTAN_HAS_ASN1
