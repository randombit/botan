/*
* Prime Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* Generate a random prime
*/
BigInt random_prime(RandomNumberGenerator& rng,
                    size_t bits, const BigInt& coprime,
                    size_t equiv, size_t modulo)
   {
   if(coprime <= 0)
      {
      throw Invalid_Argument("random_prime: coprime must be > 0");
      }
   if(modulo % 2 == 1 || modulo == 0)
      {
      throw Invalid_Argument("random_prime: Invalid modulo value");
      }
   if(equiv >= modulo || equiv % 2 == 0)
      {
      throw Invalid_Argument("random_prime: equiv must be < modulo, and odd");
      }

   // Handle small values:
   if(bits <= 1)
      {
      throw Invalid_Argument("random_prime: Can't make a prime of " +
                             std::to_string(bits) + " bits");
      }
   else if(bits == 2)
      {
      return ((rng.next_byte() % 2) ? 2 : 3);
      }
   else if(bits == 3)
      {
      return ((rng.next_byte() % 2) ? 5 : 7);
      }
   else if(bits == 4)
      {
      return ((rng.next_byte() % 2) ? 11 : 13);
      }

   while(true)
      {
      BigInt p(rng, bits);

      // Force lowest and two top bits on
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      if(p % modulo != equiv)
         p += (modulo - p % modulo) + equiv;

      const size_t sieve_size = std::min(bits / 2, PRIME_TABLE_SIZE);
      secure_vector<u16bit> sieve(sieve_size);

      for(size_t j = 0; j != sieve.size(); ++j)
         sieve[j] = static_cast<u16bit>(p % PRIMES[j]);

      size_t counter = 0;
      while(true)
         {
         ++counter;

         if(counter >= 4096)
            {
            break; // don't try forever, choose a new starting point
            }

         p += modulo;

         if(p.bits() > bits)
            break;

         bool passes_sieve = true;
         for(size_t j = 0; j != sieve.size(); ++j)
            {
            sieve[j] = (sieve[j] + modulo) % PRIMES[j];
            if(sieve[j] == 0)
               {
               passes_sieve = false;
               break;
               }
            }

         if(!passes_sieve)
            continue;

         if(gcd(p - 1, coprime) != 1)
            continue;

         if(is_prime(p, rng, 128, true))
            {
            return p;
            }
         }
      }
   }

/*
* Generate a random safe prime
*/
BigInt random_safe_prime(RandomNumberGenerator& rng, size_t bits)
   {
   if(bits <= 64)
      throw Invalid_Argument("random_safe_prime: Can't make a prime of " +
                             std::to_string(bits) + " bits");

   BigInt p;
   do
      p = (random_prime(rng, bits - 1) << 1) + 1;
   while(!is_prime(p, rng, 128, true));

   return p;
   }

}
