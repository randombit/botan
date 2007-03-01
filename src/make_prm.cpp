/*************************************************
* Prime Generation Source File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/numthry.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Generate a random prime                        *
*************************************************/
BigInt random_prime(u32bit bits, const BigInt& coprime,
                    u32bit equiv, u32bit modulo)
   {
   if(bits < 48)
      throw Invalid_Argument("random_prime: Can't make a prime of " +
                             to_string(bits) + " bits");

   if(coprime <= 0)
      throw Invalid_Argument("random_prime: coprime must be > 0");
   if(modulo % 2 == 1 || modulo == 0)
      throw Invalid_Argument("random_prime: Invalid modulo value");
   if(equiv >= modulo || equiv % 2 == 0)
      throw Invalid_Argument("random_prime: equiv must be < modulo, and odd");

   while(true)
      {
      global_state().pulse(PRIME_SEARCHING);

      BigInt p = random_integer(bits);
      p.set_bit(bits - 2);
      p.set_bit(0);

      if(p % modulo != equiv)
         p += (modulo - p % modulo) + equiv;

      const u32bit sieve_size = std::min(bits / 2, PRIME_TABLE_SIZE);
      SecureVector<u32bit> sieve(sieve_size);

      for(u32bit j = 0; j != sieve.size(); ++j)
         {
         sieve[j] = p % PRIMES[j];
         global_state().pulse(PRIME_SIEVING);
         }

      u32bit counter = 0;
      while(true)
         {
         if(counter == 4096 || p.bits() > bits)
            break;

         global_state().pulse(PRIME_SEARCHING);

         bool passes_sieve = true;
         ++counter;
         p += modulo;

         for(u32bit j = 0; j != sieve.size(); ++j)
            {
            sieve[j] = (sieve[j] + modulo) % PRIMES[j];
            global_state().pulse(PRIME_SIEVING);
            if(sieve[j] == 0)
               passes_sieve = false;
            }

         if(!passes_sieve || gcd(p - 1, coprime) != 1)
            continue;
         global_state().pulse(PRIME_PASSED_SIEVE);
         if(passes_mr_tests(p))
            {
            global_state().pulse(PRIME_FOUND);
            return p;
            }
         }
      }
   }

}
