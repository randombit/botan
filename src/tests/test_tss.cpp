/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)

#include <botan/tss.h>

size_t test_tss()
   {
   using namespace Botan;

   AutoSeeded_RNG rng;

   size_t fails = 0;

   byte id[16];
   for(int i = 0; i != 16; ++i)
      id[i] = i;

   const secure_vector<byte> S = hex_decode_locked("7465737400");

   std::vector<RTSS_Share> shares =
      RTSS_Share::split(2, 4, &S[0], S.size(), id, rng);

   auto back = RTSS_Share::reconstruct(shares);

   if(S != back)
      {
      std::cout << "TSS-0: " << hex_encode(S) << " != " << hex_encode(back) << "\n";
      ++fails;
      }

   shares.resize(shares.size()-1);

   back = RTSS_Share::reconstruct(shares);

   if(S != back)
      {
      std::cout << "TSS-1: " << hex_encode(S) << " != " << hex_encode(back) << "\n";
      ++fails;
      }

   return fails;
   }
#else
size_t test_tss()
   {
   std::cout << "Skipping TSS tests\n";
   return 1;
   }
#endif
