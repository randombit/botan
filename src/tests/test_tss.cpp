/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)
  #include <botan/tss.h>
  #include <botan/hex.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)

class TSS_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         Test::Result result("TSS");
         uint8_t id[16];
         for(int i = 0; i != 16; ++i)
            id[i] = i;

         const std::vector<uint8_t> S = Botan::hex_decode("7465737400");

         std::vector<Botan::RTSS_Share> shares =
            Botan::RTSS_Share::split(2, 4, S.data(), S.size(), id, Test::rng());

         result.test_eq("reconstruction", Botan::RTSS_Share::reconstruct(shares), S);
         shares.resize(shares.size()-1);
         result.test_eq("reconstruction after removal", Botan::RTSS_Share::reconstruct(shares), S);

         results.push_back(result);
         return results;
         }
   };

BOTAN_REGISTER_TEST("tss", TSS_Tests);

#endif // BOTAN_HAS_THRESHOLD_SECRET_SHARING

}

}
