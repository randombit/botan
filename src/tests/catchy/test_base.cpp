// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"
#include <botan/symkey.h>

using namespace Botan;

TEST_CASE("OctetString", "[base]")
   {   
   auto empty = secure_vector<byte>{ };
   auto one   = secure_vector<byte>{ 94 }; // ^
   auto some  = secure_vector<byte>{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // Hello
   auto utf8  = secure_vector<byte>{ 0xc3, 0xb6 }; // ö

   auto os_empty = OctetString("");
   auto os_one   = OctetString("5e");
   auto os_some  = OctetString("48656c6c6f");
   auto os_utf8  = OctetString("c3b6");

   CHECK_THAT(os_empty.bits_of(), Equals(empty));
   CHECK_THAT(os_one.bits_of(),   Equals(one));
   CHECK_THAT(os_some.bits_of(),  Equals(some));
   CHECK_THAT(os_utf8.bits_of(),  Equals(utf8));
   }
