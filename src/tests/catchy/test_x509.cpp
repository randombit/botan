// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catch.hpp"
#include <botan/build.h>

// deacticate due to
// https://github.com/randombit/botan/issues/185

#if 0

#if defined(BOTAN_HAS_ASN1)

#include <botan/asn1_time.h>

TEST_CASE("human readable time", "[X509]")
   {
   auto time1 = Botan::X509_Time("2008-02-01");
   auto time2 = Botan::X509_Time("2008-02-01 17:24:33");
   auto time3 = Botan::X509_Time("2004-06-14T23:34:30");

   CHECK(( time1.time_is_set() == true ));
   CHECK(( time2.time_is_set() == true ));
   CHECK(( time3.time_is_set() == true ));

   CHECK(( time1.readable_string() == "2008/02/01 00:00:00 UTC" ));
   CHECK(( time2.readable_string() == "2008/02/01 17:24:33 UTC" ));
   CHECK(( time3.readable_string() == "2004/06/14 23:34:30 UTC" ));
   }

TEST_CASE("no time", "[X509]")
   {
   auto time = Botan::X509_Time("");
   CHECK(( time.time_is_set() == false ));
   }

TEST_CASE("invalid time", "[X509]")
   {
   CHECK_THROWS( Botan::X509_Time(" ") );
   CHECK_THROWS( Botan::X509_Time("2008`02-01") );
   CHECK_THROWS( Botan::X509_Time("9999-02-01") );
   CHECK_THROWS( Botan::X509_Time("2000-02-01 17") );
   CHECK_THROWS( Botan::X509_Time("999921") );
   }

#endif // BOTAN_HAS_ASN1

#endif
