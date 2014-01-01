/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/tss.h>
#include <iostream>
#include <stdio.h>

namespace {

void print(const Botan::secure_vector<Botan::byte>& r)
   {
   for(Botan::u32bit i = 0; i != r.size(); ++i)
      printf("%02X", r[i]);
   printf("\n");
   }

}

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
