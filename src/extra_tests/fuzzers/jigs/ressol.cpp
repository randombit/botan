/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/numthry.h>

void fuzz(const uint8_t in[], size_t len)
   {
   /*
   * This allows two values (a,p) up to 768 bits in length, which is
   * sufficient to test ressol (modular square root) for since it is
   * mostly used for ECC.
   */
   if(len % 2 != 0 || len > 2 * (768 / 8))
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
            if(is_prime(n, fuzzer_rng(), 64))
               {
               std::cout << "A = " << a << "\n";
               std::cout << "N = " << n << "\n";
               std::cout << "Ressol = " << a_sqrt << "\n";
               std::cout << "recomputed = " << z << "\n";
               abort();
               }
            }
         }
      }
   catch(Botan::Exception& e) {}

   return;
   }

