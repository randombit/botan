/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/tss.h>
#include <iostream>
#include <stdio.h>

namespace {

void print(const Botan::SecureVector<Botan::byte>& r)
   {
   for(Botan::u32bit i = 0; i != r.size(); ++i)
      printf("%02X", r[i]);
   printf("\n");
   }

}

int main()
   {
   using namespace Botan;

   LibraryInitializer init;

   AutoSeeded_RNG rng;

   byte id[16];
   for(int i = 0; i != 16; ++i)
      id[i] = i;

   const byte S2[] = { 0xDE, 0xAD, 0xCA, 0xFE, 0xBA, 0xBE, 0xBE, 0xEF };

   std::vector<RTSS_Share> shares =
      RTSS_Share::split(4, 6, S2, sizeof(S2), id, rng);

   for(size_t i = 0; i != shares.size(); ++i)
      std::cout << i << " = " << shares[i].to_string() << "\n";

   print(RTSS_Share::reconstruct(shares));
   }
