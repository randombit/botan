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

TEST_CASE("Bigint random_integer", "[bigint]")
   {
   RandomNumberGenerator *rng = RandomNumberGenerator::make_rng();

   SECTION("min is 0")
      {
      // 0–9
      const size_t MIN = 0;
      const size_t MAX = 10; // excluded
      const int ITERATIONS = 10000;

      std::vector<int> counts(MAX, 0);
      std::vector<double> ratios(MAX, 1.0);

      for (size_t i = 0; i < ITERATIONS; i++)
         {
         BigInt b = BigInt::random_integer(*rng, MIN, MAX);
         size_t x = b.to_u32bit();
         counts[x]++;
         }

      std::stringstream debug;
      for (size_t d = MIN; d < MAX; ++d)
         {
         auto ratio = static_cast<double>(counts[d]) / ITERATIONS;
         ratios[d] = ratio;

         if (!debug.str().empty())
            {
            debug << ", ";
            }
         debug << d << ": " << std::setprecision(3) << ratio;
         }

      INFO( debug.str() )

      // Have ~ 10 % on each digit from 0-9
      CHECK(( 0.09 < ratios[0] )); CHECK(( ratios[0] < 0.11 ));
      CHECK(( 0.09 < ratios[1] )); CHECK(( ratios[1] < 0.11 ));
      CHECK(( 0.09 < ratios[2] )); CHECK(( ratios[2] < 0.11 ));
      CHECK(( 0.09 < ratios[3] )); CHECK(( ratios[3] < 0.11 ));
      CHECK(( 0.09 < ratios[4] )); CHECK(( ratios[4] < 0.11 ));
      CHECK(( 0.09 < ratios[5] )); CHECK(( ratios[5] < 0.11 ));
      CHECK(( 0.09 < ratios[6] )); CHECK(( ratios[6] < 0.11 ));
      CHECK(( 0.09 < ratios[7] )); CHECK(( ratios[7] < 0.11 ));
      CHECK(( 0.09 < ratios[8] )); CHECK(( ratios[8] < 0.11 ));
      CHECK(( 0.09 < ratios[9] )); CHECK(( ratios[9] < 0.11 ));
      //CHECK( false );
      }

   SECTION("min is 10")
      {
      // 10–19
      const size_t MIN = 10;
      const size_t MAX = 20; // excluded
      const size_t ITERATIONS = 10000;

      std::vector<int> counts(MAX, 0);
      std::vector<double> ratios(MAX, 1.0);

      for (size_t i = 0; i < ITERATIONS; i++)
         {
         BigInt b = BigInt::random_integer(*rng, MIN, MAX);
         size_t x = b.to_u32bit();
         counts[x]++;
         }

      std::stringstream debug;
      for (size_t d = MIN; d < MAX; ++d)
         {
         auto ratio = static_cast<double>(counts[d]) / ITERATIONS;
         ratios[d] = ratio;

         if (!debug.str().empty())
            {
            debug << ", ";
            }
         debug << d << ": " << std::setprecision(3) << ratio;
         }

      INFO( debug.str() )

      // Have ~ 10 % on each digit from 10-19
      CHECK(( 0.09 < ratios[10] )); CHECK(( ratios[10] < 0.11 ));
      CHECK(( 0.09 < ratios[11] )); CHECK(( ratios[11] < 0.11 ));
      CHECK(( 0.09 < ratios[12] )); CHECK(( ratios[12] < 0.11 ));
      CHECK(( 0.09 < ratios[13] )); CHECK(( ratios[13] < 0.11 ));
      CHECK(( 0.09 < ratios[14] )); CHECK(( ratios[14] < 0.11 ));
      CHECK(( 0.09 < ratios[15] )); CHECK(( ratios[15] < 0.11 ));
      CHECK(( 0.09 < ratios[16] )); CHECK(( ratios[16] < 0.11 ));
      CHECK(( 0.09 < ratios[17] )); CHECK(( ratios[17] < 0.11 ));
      CHECK(( 0.09 < ratios[18] )); CHECK(( ratios[18] < 0.11 ));
      CHECK(( 0.09 < ratios[19] )); CHECK(( ratios[19] < 0.11 ));
      //CHECK( false );
      }
   }

#endif
