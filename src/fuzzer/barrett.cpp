/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/numthry.h>
#include <botan/reducer.h>

void fuzz(const uint8_t in[], size_t len)
   {
   static const size_t max_bits = 2048;

   if(len % 2 != 0)
      return;

   const size_t part_size = len / 2;

   if(part_size * 8 > max_bits)
      return;

   const Botan::BigInt x = Botan::BigInt::decode(in, part_size);
   const Botan::BigInt p = Botan::BigInt::decode(in + part_size, part_size);

   if(p.is_zero())
      return;

   const Botan::BigInt ref = x % p;

   const Botan::Modular_Reducer mod_p(p);
   const Botan::BigInt z = mod_p.reduce(x);

   if(ref != z)
      {
      FUZZER_WRITE_AND_CRASH("X = " << x << "\n"
                             << "P = " << p << "\n"
                             << "Z = " << z << "\n"
                             << "R = " << ref << "\n");
      }
   }
