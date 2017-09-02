/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/numthry.h>
#include <botan/reducer.h>

void fuzz(const uint8_t in[], size_t len)
   {
   // Ressol is mostly used for ECC point decompression so best to test smaller sizes
   static const size_t p_bits = 256;
   static const Botan::BigInt p = random_prime(fuzzer_rng(), p_bits);
   static const Botan::Modular_Reducer mod_p(p);

   if(len > p_bits / 8)
      return;

   try
      {
      const Botan::BigInt a = Botan::BigInt::decode(in, len);
      Botan::BigInt a_sqrt = Botan::ressol(a, p);

      if(a_sqrt > 0)
         {
         const Botan::BigInt a_redc = mod_p.reduce(a);
         const Botan::BigInt z = mod_p.square(a_sqrt);

         if(z != a_redc)
            {
            FUZZER_WRITE_AND_CRASH("A = " << a << "\n"
                                   << "P = " << p << "\n"
                                   << "R = " << a_sqrt << "\n"
                                   << "Z = " << z << "\n");
            }
         }
      }
   catch(Botan::Exception& e) {}

   return;
   }

