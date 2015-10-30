/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)

#include <iostream>
#include <botan/hex.h>
#include <botan/tss.h>

size_t test_tss()
   {
   using namespace Botan;

   auto& rng = test_rng();

   size_t fails = 0;

   byte id[16];
   for(int i = 0; i != 16; ++i)
      id[i] = i;

   const secure_vector<byte> S = hex_decode_locked("7465737400");

   std::vector<RTSS_Share> shares =
      RTSS_Share::split(2, 4, S.data(), S.size(), id, rng);

   fails += test_buffers_equal("TSS", "test 1", RTSS_Share::reconstruct(shares), S);

   shares.resize(shares.size()-1);
   fails += test_buffers_equal("TSS", "test 2", RTSS_Share::reconstruct(shares), S);

   test_report("TSS", 2, fails);

   return fails;
   }

#else

SKIP_TEST(tss);

#endif // BOTAN_HAS_THRESHOLD_SECRET_SHARING
