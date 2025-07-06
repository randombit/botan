/*
* (C) 2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/numthry.h>
#include <botan/internal/barrett.h>
#include <botan/internal/divide.h>

void fuzz(std::span<const uint8_t> in) {
   static const size_t max_bits = 4096;

   if(in.size() <= 4) {
      return;
   }

   if(in.size() > 2 * (max_bits / 8)) {
      return;
   }

   const size_t x_len = 2 * in.size() / 3;

   const Botan::BigInt x = Botan::BigInt::from_bytes(in.subspan(0, x_len));
   const Botan::BigInt p = Botan::BigInt::from_bytes(in.subspan(x_len, in.size() - x_len));

   if(p.is_zero()) {
      return;
   }

   try {
      const auto mod_p = Botan::Barrett_Reduction::for_public_modulus(p);
      const Botan::BigInt z = mod_p.reduce(x);

      const Botan::BigInt ref = x % p;
      const Botan::BigInt ct = ct_modulo(x, p);

      if(ref != z || ref != ct) {
         FUZZER_WRITE_AND_CRASH("X = " << x.to_hex_string() << "\n"
                                       << "P = " << p.to_hex_string() << "\n"
                                       << "Barrett = " << z.to_hex_string() << "\n"
                                       << "Ct = " << ct.to_hex_string() << "\n"
                                       << "Ref = " << ref.to_hex_string() << "\n");
      }
   } catch(Botan::Invalid_Argument&) {}
}
