/*
* (C) 2016,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/numthry.h>
#include <botan/reducer.h>

namespace {

Botan::BigInt simple_power_mod(Botan::BigInt x, Botan::BigInt n, const Botan::BigInt& p) {
   if(n == 0) {
      if(p == 1) {
         return 0;
      }
      return 1;
   }

   Botan::Modular_Reducer mod_p(p);
   Botan::BigInt y = 1;

   while(n > 1) {
      if(n.is_odd()) {
         y = mod_p.multiply(x, y);
      }
      x = mod_p.square(x);
      n >>= 1;
   }
   return mod_p.multiply(x, y);
}

}  // namespace

void fuzz(const uint8_t in[], size_t len) {
   static const size_t max_bits = 2048;

   if(len % 3 != 0) {
      return;
   }

   const size_t part_size = len / 3;

   if(part_size * 8 > max_bits) {
      return;
   }

   const Botan::BigInt g = Botan::BigInt::decode(in, part_size);
   const Botan::BigInt x = Botan::BigInt::decode(in + part_size, part_size);
   const Botan::BigInt p = Botan::BigInt::decode(in + 2 * part_size, part_size);

   try {
      const Botan::BigInt ref = simple_power_mod(g, x, p);
      const Botan::BigInt z = Botan::power_mod(g, x, p);

      if(ref != z) {
         FUZZER_WRITE_AND_CRASH("G = " << g << "\n"
                                       << "X = " << x << "\n"
                                       << "P = " << p << "\n"
                                       << "Z = " << z << "\n"
                                       << "R = " << ref << "\n");
      }
   } catch(Botan::Exception& e) {}
}
