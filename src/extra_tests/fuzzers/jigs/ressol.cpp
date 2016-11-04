/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/numthry.h>
#include <botan/system_rng.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len % 2 != 0)
      return;

   const BigInt a = BigInt::decode(in, len / 2);
   const BigInt n = BigInt::decode(in + len / 2, len / 2);

   try {
       BigInt a_sqrt = ressol(a, n);

      if(a_sqrt > 0)
         {
         /*
         * If n is not prime then the result of ressol will be bogus. But
         * this function is exposed to untrusted inputs (via OS2ECP) so
         * should not hang or crash even with composite modulus.
         * If the result is incorrect, check if n is a prime: if it is
         * then z != a is a bug.
         */
         BigInt z = (a_sqrt * a_sqrt) % n;
         BigInt a_redc = a % n;
         if(z != a_redc)
            {
            if(is_prime(n, system_rng(), 64))
               {
               std::cout << "A = " << a << "\n";
               std::cout << "Ressol = " << a_sqrt << "\n";
               std::cout << "N = " << n << "\n";
               std::cout << "Z = " << z << "\n";
               abort();
               }
            }
         }
      }
   catch(Botan::Exception& e) {}

   return;
   }

