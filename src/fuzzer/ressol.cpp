/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/numthry.h>
#include <botan/internal/barrett.h>

void fuzz(std::span<const uint8_t> in) {
   // Ressol is mostly used for ECC point decompression so best to test smaller sizes
   static const size_t p_bits = 256;
   // Use p == 1 mod 4 since sqrt modulo p == 3 mod 4 is a fast case
   static const Botan::BigInt p = random_prime(fuzzer_rng(), p_bits, 0, 1, 4);
   static auto mod_p = Botan::Barrett_Reduction::for_public_modulus(p);

   if(in.size() > p_bits / 8) {
      return;
   }

   try {
      const Botan::BigInt a = Botan::BigInt::from_bytes(in);
      const Botan::BigInt a_sqrt = Botan::sqrt_modulo_prime(a, p);

      if(a_sqrt > 0) {
         const Botan::BigInt a_redc = mod_p.reduce(a);
         const Botan::BigInt z = mod_p.square(a_sqrt);

         if(z != a_redc) {
            FUZZER_WRITE_AND_CRASH("A = " << a.to_hex_string() << "\n"
                                          << "P = " << p.to_hex_string() << "\n"
                                          << "R = " << a_sqrt.to_hex_string() << "\n"
                                          << "Z = " << z.to_hex_string() << "\n");
         }
      }
   } catch(Botan::Exception& e) {}
}
