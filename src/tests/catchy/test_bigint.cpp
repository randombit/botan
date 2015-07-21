// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catch.hpp"

#include <botan/build.h>

#if defined(BOTAN_HAS_BIGINT)

#include <botan/bigint.h>

using namespace Botan;

TEST_CASE("Bigint basics", "[bigint]")
   {
   SECTION("in 0-bit border")
      {
      BigInt a(0u);
      CHECK(( a.bits() == 0 ));
      CHECK(( a.bytes() == 0 ));
      CHECK(( a.to_u32bit() == 0 ));
      }
   SECTION("above 0-bit border")
      {
      BigInt a(1u);
      CHECK(( a.bits() == 1 ));
      CHECK(( a.bytes() == 1 ));
      CHECK(( a.to_u32bit() == 1 ));
      }
   SECTION("in 8-bit border")
      {
      BigInt a(255u);
      CHECK(( a.bits() == 8 ));
      CHECK(( a.bytes() == 1 ));
      CHECK(( a.to_u32bit() == 255 ));
      }
   SECTION("above 8-bit border")
      {
      BigInt a(256u);
      CHECK(( a.bits() == 9 ));
      CHECK(( a.bytes() == 2 ));
      CHECK(( a.to_u32bit() == 256 ));
      }
   SECTION("in 16-bit border")
      {
      BigInt a(65535u);
      CHECK(( a.bits() == 16 ));
      CHECK(( a.bytes() == 2 ));
      CHECK(( a.to_u32bit() == 65535 ));
      }
   SECTION("above 16-bit border")
      {
      BigInt a(65536u);
      CHECK(( a.bits() == 17 ));
      CHECK(( a.bytes() == 3 ));
      CHECK(( a.to_u32bit() == 65536 ));
      }
   SECTION("in 32-bit border")
      {
      BigInt a(4294967295u);
      CHECK(( a.bits() == 32 ));
      CHECK(( a.bytes() == 4 ));
      CHECK(( a.to_u32bit() == 4294967295u ));
      }
   SECTION("above 32-bit border")
      {
      BigInt a(4294967296u);
      CHECK(( a.bits() == 33 ));
      CHECK(( a.bytes() == 5 ));
      CHECK_THROWS( a.to_u32bit() );
      }
   }

#endif
