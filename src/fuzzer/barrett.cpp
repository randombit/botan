/*
* (C) 2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/divide.h>

void fuzz(std::span<const uint8_t> in) {
   static const size_t max_bits = 4096;

   if(in.size() <= 4) {
      return;
   }

   if(in.size() > 2 * (max_bits / 8)) {
      return;
   }

   const size_t x_len = 2 * ((in.size() + 2) / 3);

   Botan::BigInt x = Botan::BigInt::from_bytes(in.subspan(0, x_len));
   const Botan::BigInt p = Botan::BigInt::from_bytes(in.subspan(x_len, in.size() - x_len));

   if(p.is_zero()) {
      return;
   }

   const size_t x_bits = x.bits();
   if(x_bits % 8 == 0 && x_bits / 8 == x_len) {
      x.flip_sign();
   }

   const Botan::BigInt ref = x % p;

   const Botan::Modular_Reducer mod_p(p);
   const Botan::BigInt z = mod_p.reduce(x);

   const Botan::BigInt ct = ct_modulo(x, p);

   if(ref != z || ref != ct) {
      FUZZER_WRITE_AND_CRASH("X = " << x.to_hex_string() << "\n"
                                    << "P = " << p.to_hex_string() << "\n"
                                    << "Barrett = " << z.to_hex_string() << "\n"
                                    << "Ct = " << ct.to_hex_string() << "\n"
                                    << "Ref = " << ref.to_hex_string() << "\n");
   }
}
