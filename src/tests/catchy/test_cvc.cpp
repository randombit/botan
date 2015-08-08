// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"

#if defined(BOTAN_HAS_CVC)

#include <botan/eac_asn_obj.h>

TEST_CASE("human readable time", "[EAC_Time]")
   {
   auto time1 = Botan::EAC_Time("2008-02-01");
   auto time2 = Botan::EAC_Time("2008/02/28");
   auto time3 = Botan::EAC_Time("2004-06-14");

   CHECK(( time1.time_is_set() == true ));
   CHECK(( time2.time_is_set() == true ));
   CHECK(( time3.time_is_set() == true ));

   CHECK(( time1.readable_string() == "2008/02/01" ));
   CHECK(( time2.readable_string() == "2008/02/28" ));
   CHECK(( time3.readable_string() == "2004/06/14" ));
   }

TEST_CASE("no time", "[EAC_Time]")
   {
   auto time = Botan::EAC_Time("");
   CHECK(( time.time_is_set() == false ));
   }

TEST_CASE("invalis time", "[EAC_Time]")
   {
   CHECK_THROWS( Botan::EAC_Time(" ") );
   CHECK_THROWS( Botan::EAC_Time("2008`02-01") );
   CHECK_THROWS( Botan::EAC_Time("9999-02-01") );
   CHECK_THROWS( Botan::EAC_Time("2000-02-01 17") );
   CHECK_THROWS( Botan::EAC_Time("999921") );
   }

#endif // BOTAN_HAS_CVC
