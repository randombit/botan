/*
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/numthry.h>

namespace {

Botan::BigInt ref_gcd(Botan::BigInt a,
                      Botan::BigInt b)
   {
   Botan::BigInt t;
   while(b != 0)
      {
      t = b;
      b = a % b;
      a = t;
      }
   return a;
   }

}

void fuzz(const uint8_t in[], size_t len)
   {
   static const size_t max_bits = 4096;

   const size_t part_size = len / 2;

   if(part_size * 8 > max_bits)
      return;

   const Botan::BigInt x = Botan::BigInt::decode(in, part_size);
   const Botan::BigInt y = Botan::BigInt::decode(in + part_size, part_size);

   if(x == 0 || y == 0)
      return;

   const Botan::BigInt ref = ref_gcd(x, y);
   const Botan::BigInt lib = Botan::gcd(x, y);

   if(ref != lib)
      {
      FUZZER_WRITE_AND_CRASH("X = " << x << "\n"
                             << "Y = " << y << "\n"
                             << "L = " << lib << "\n"
                             << "R = " << ref << "\n");
      }
   }
