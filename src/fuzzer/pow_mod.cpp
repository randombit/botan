/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>

namespace {

Botan::BigInt simple_power_mod(Botan::BigInt x,
                               Botan::BigInt n,
                               const Botan::BigInt& p,
                               const Botan::Modular_Reducer& mod_p)
   {
   if(n == 0)
      {
      if(p == 1)
         return 0;
      return 1;
      }

   Botan::BigInt y = 1;

   while(n > 1)
      {
      if(n.is_odd())
         {
         y = mod_p.multiply(x, y);
         }
      x = mod_p.square(x);
      n >>= 1;
      }
   return mod_p.multiply(x, y);
   }

}

void fuzz(const uint8_t in[], size_t len)
   {
   static const size_t p_bits = 1024;
   static const Botan::BigInt p = random_prime(fuzzer_rng(), p_bits);
   static Botan::Modular_Reducer mod_p(p);

   if(len == 0 || len > p_bits/8)
      return;

   try
      {
      const Botan::BigInt g = Botan::BigInt::decode(in, len / 2);
      const Botan::BigInt x = Botan::BigInt::decode(in + len / 2, len / 2);

      const Botan::BigInt ref = simple_power_mod(g, x, p, mod_p);
      const Botan::BigInt z = Botan::power_mod(g, x, p);

      if(ref != z)
         {
         FUZZER_WRITE_AND_CRASH("G = " << g << "\n"
                                << "X = " << x << "\n"
                                << "P = " << p << "\n"
                                << "Z = " << z << "\n"
                                << "R = " << ref << "\n");
         }
      }
   catch(Botan::Exception& e) {}
   }
