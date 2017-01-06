/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/numthry.h>
#include <botan/reducer.h>

void fuzz(const uint8_t in[], size_t len)
   {
   // Ressol is mostly used for ECC point decompression so best to test smaller sizes
   static const size_t p_bits = 256;
   static const BigInt p = random_prime(fuzzer_rng(), p_bits);
   static const Modular_Reducer mod_p(p);

   if(len > p_bits / 8)
      return;

   try
      {
      const BigInt a = BigInt::decode(in, len);
      BigInt a_sqrt = Botan::ressol(a, p);

      if(a_sqrt > 0)
         {
         const BigInt a_redc = mod_p.reduce(a);
         const BigInt z = mod_p.square(a_sqrt);

         if(z != a_redc)
            {
            std::cout << "A = " << a << "\n";
            std::cout << "P = " << p << "\n";
            std::cout << "R = " << a_sqrt << "\n";
            std::cout << "Z = " << z << "\n";
            abort();
            }
         }
      }
   catch(Botan::Exception& e) {}

   return;
   }

