/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>

BigInt simple_power_mod(BigInt x, BigInt n, const BigInt& p)
   {
   if(n == 0)
      {
      if(p == 1)
         return 0;
      return 1;
      }

   Modular_Reducer mod_p(p);
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
   if(len % 3 != 0 || len > 3 * (2048/8))
      return;

   const size_t part_size = len / 3;

   try
      {
      const BigInt g = BigInt::decode(in, part_size);
      const BigInt x = BigInt::decode(in + part_size, part_size);
      const BigInt p = BigInt::decode(in + 2 * (part_size), part_size);
      const BigInt ref = simple_power_mod(g, x, p);
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
