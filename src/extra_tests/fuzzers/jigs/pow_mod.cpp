/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>

BigInt simple_power_mod(BigInt x, BigInt n, const BigInt& p, const Modular_Reducer& mod_p)
   {
   if(n == 0)
      {
      if(p == 1)
         return 0;
      return 1;
      }

   BigInt y = 1;

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

void fuzz(const uint8_t in[], size_t len)
   {
   static const size_t p_bits = 1024;
   static const BigInt p = random_prime(fuzzer_rng(), p_bits);
   static Modular_Reducer mod_p(p);

   if(len == 0 || len > p_bits/8)
      return;

   try
      {
      const BigInt g = BigInt::decode(in, len / 2);
      const BigInt x = BigInt::decode(in + len / 2, len / 2);

      const BigInt ref = simple_power_mod(g, x, p, mod_p);
      const BigInt z = Botan::power_mod(g, x, p);

      if(ref != z)
         {
         std::cout << "G = " << g << "\n"
                   << "X = " << x << "\n"
                   << "P = " << p << "\n"
                   << "Z = " << z << "\n"
                   << "R = " << ref << "\n";
         abort();
         }
      }
   catch(Botan::Exception& e) {}
   }
