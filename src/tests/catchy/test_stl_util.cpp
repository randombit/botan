// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"

#include <botan/internal/stl_util.h>

TEST_CASE("secure vector to string", "[STL_Util]")
   {
   using namespace Botan;
   auto empty = secure_vector<byte>{ };
   auto one   = secure_vector<byte>{ 94 };
   auto some  = secure_vector<byte>{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
   // echo -n "ö" | hexdump -C
   auto utf8  = secure_vector<byte>{ 0xc3, 0xb6 };

   CHECK_THAT(to_string(empty), Equals(""));
   CHECK_THAT(to_string(one),   Equals("^"));
   CHECK_THAT(to_string(some),  Equals("Hello"));
   CHECK_THAT(to_string(utf8),  Equals("ö"));
   }
