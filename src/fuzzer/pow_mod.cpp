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

void fuzz(std::span<const uint8_t> in) {
   static const size_t max_bits = 2048;

   if(in.size() % 3 != 0) {
      return;
   }

   const size_t part_size = in.size() / 3;

   if(part_size * 8 > max_bits) {
      return;
   }

   const Botan::BigInt g = Botan::BigInt::from_bytes(in.subspan(0, part_size));
   const Botan::BigInt x = Botan::BigInt::from_bytes(in.subspan(part_size, part_size));
   const Botan::BigInt p = Botan::BigInt::from_bytes(in.subspan(2 * part_size, part_size));

   try {
      const Botan::BigInt ref = simple_power_mod(g, x, p);
      const Botan::BigInt z = Botan::power_mod(g, x, p);

      if(ref != z) {
         FUZZER_WRITE_AND_CRASH("G = " << g.to_hex_string() << "\n"
                                       << "X = " << x.to_hex_string() << "\n"
                                       << "P = " << p.to_hex_string() << "\n"
                                       << "Z = " << z.to_hex_string() << "\n"
                                       << "R = " << ref.to_hex_string() << "\n");
      }
   } catch(Botan::Exception& e) {}
}
