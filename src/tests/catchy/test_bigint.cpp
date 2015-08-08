// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#include "catchy_tests.h"

#if defined(BOTAN_HAS_BIGINT)

#include <botan/bigint.h>

using namespace Botan;

TEST_CASE("Bigint basics", "[bigint]")
   {
   SECTION("in 0-bit border")
      {
      BigInt a(0u);
      CHECK_THAT(a.bits(),      Equals(0));
      CHECK_THAT(a.bytes(),     Equals(0));
      CHECK_THAT(a.to_u32bit(), Equals(0));
      }
   SECTION("above 0-bit border")
      {
      BigInt a(1u);
      CHECK_THAT(a.bits(),      Equals(1));
      CHECK_THAT(a.bytes(),     Equals(1));
      CHECK_THAT(a.to_u32bit(), Equals(1));
      }
   SECTION("in 8-bit border")
      {
      BigInt a(255u);
      CHECK_THAT(a.bits(),      Equals(8));
      CHECK_THAT(a.bytes(),     Equals(1));
      CHECK_THAT(a.to_u32bit(), Equals(255));
      }
   SECTION("above 8-bit border")
      {
      BigInt a(256u);
      CHECK_THAT(a.bits(),      Equals(9));
      CHECK_THAT(a.bytes(),     Equals(2));
      CHECK_THAT(a.to_u32bit(), Equals(256));
      }
   SECTION("in 16-bit border")
      {
      BigInt a(65535u);
      CHECK_THAT(a.bits(),      Equals(16));
      CHECK_THAT(a.bytes(),     Equals(2));
      CHECK_THAT(a.to_u32bit(), Equals(65535));
      }
   SECTION("above 16-bit border")
      {
      BigInt a(65536u);
      CHECK_THAT(a.bits(),      Equals(17));
      CHECK_THAT(a.bytes(),     Equals(3));
      CHECK_THAT(a.to_u32bit(), Equals(65536));
      }
   SECTION("in 32-bit border")
      {
      BigInt a(4294967295u);
      CHECK_THAT(a.bits(),      Equals(32));
      CHECK_THAT(a.bytes(),     Equals(4));
      CHECK_THAT(a.to_u32bit(), Equals(4294967295u));
      }
   SECTION("above 32-bit border")
      {
      BigInt a(4294967296u);
      CHECK_THAT(a.bits(),  Equals(33));
      CHECK_THAT(a.bytes(), Equals(5));
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
      CHECK(( 0.085 <= ratios[0] )); CHECK(( ratios[0] <= 0.115 ));
      CHECK(( 0.085 <= ratios[1] )); CHECK(( ratios[1] <= 0.115 ));
      CHECK(( 0.085 <= ratios[2] )); CHECK(( ratios[2] <= 0.115 ));
      CHECK(( 0.085 <= ratios[3] )); CHECK(( ratios[3] <= 0.115 ));
      CHECK(( 0.085 <= ratios[4] )); CHECK(( ratios[4] <= 0.115 ));
      CHECK(( 0.085 <= ratios[5] )); CHECK(( ratios[5] <= 0.115 ));
      CHECK(( 0.085 <= ratios[6] )); CHECK(( ratios[6] <= 0.115 ));
      CHECK(( 0.085 <= ratios[7] )); CHECK(( ratios[7] <= 0.115 ));
      CHECK(( 0.085 <= ratios[8] )); CHECK(( ratios[8] <= 0.115 ));
      CHECK(( 0.085 <= ratios[9] )); CHECK(( ratios[9] <= 0.115 ));
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
      CHECK(( 0.085 <= ratios[10] )); CHECK(( ratios[10] <= 0.115 ));
      CHECK(( 0.085 <= ratios[11] )); CHECK(( ratios[11] <= 0.115 ));
      CHECK(( 0.085 <= ratios[12] )); CHECK(( ratios[12] <= 0.115 ));
      CHECK(( 0.085 <= ratios[13] )); CHECK(( ratios[13] <= 0.115 ));
      CHECK(( 0.085 <= ratios[14] )); CHECK(( ratios[14] <= 0.115 ));
      CHECK(( 0.085 <= ratios[15] )); CHECK(( ratios[15] <= 0.115 ));
      CHECK(( 0.085 <= ratios[16] )); CHECK(( ratios[16] <= 0.115 ));
      CHECK(( 0.085 <= ratios[17] )); CHECK(( ratios[17] <= 0.115 ));
      CHECK(( 0.085 <= ratios[18] )); CHECK(( ratios[18] <= 0.115 ));
      CHECK(( 0.085 <= ratios[19] )); CHECK(( ratios[19] <= 0.115 ));
      //CHECK( false );
      }
   }

#endif
