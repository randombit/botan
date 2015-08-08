// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"

#if defined(BOTAN_HAS_ASN1)

#include <botan/asn1_time.h>

using namespace Botan;

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

TEST_CASE("no time", "[X509]")
   {
   auto time = X509_Time();
   CHECK_THAT(time.time_is_set(), Equals(false));
   }

TEST_CASE("invalid time", "[X509]")
   {
   CHECK_THROWS(X509_Time("", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time(" ", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2008`02-01", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("9999-02-01", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("2000-02-01 17", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("999921", ASN1_Tag::UTC_TIME));

   // wrong time zone
   CHECK_THROWS(X509_Time("0802010000", ASN1_Tag::UTC_TIME));
   CHECK_THROWS(X509_Time("0802010000z", ASN1_Tag::UTC_TIME));
   }

#endif // BOTAN_HAS_ASN1
