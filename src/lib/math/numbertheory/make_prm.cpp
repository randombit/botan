/*
* Prime Generation
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

/*
* Generate a random prime
*/
BigInt random_prime(RandomNumberGenerator& rng,
                    size_t bits, const BigInt& coprime,
                    size_t equiv, size_t modulo,
                    size_t prob)
   {
   if(coprime.is_negative())
      {
      throw Invalid_Argument("random_prime: coprime must be >= 0");
      }
   if(modulo == 0)
      {
      throw Invalid_Argument("random_prime: Invalid modulo value");
      }

   equiv %= modulo;

   if(equiv == 0)
      throw Invalid_Argument("random_prime Invalid value for equiv/modulo");

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
   else if(bits <= 16)
      {
      for(;;)
         {
         size_t idx = make_uint16(rng.next_byte(), rng.next_byte()) % PRIME_TABLE_SIZE;
         uint16_t small_prime = PRIMES[idx];

         if(high_bit(small_prime) == bits)
            return small_prime;
         }
      }

   secure_vector<uint16_t> sieve(PRIME_TABLE_SIZE);
   const size_t MAX_ATTEMPTS = 32*1024;

   while(true)
      {
      BigInt p(rng, bits);

      // Force lowest and two top bits on
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      // Force p to be equal to equiv mod modulo
      p += (modulo - (p % modulo)) + equiv;

      for(size_t i = 0; i != sieve.size(); ++i)
         sieve[i] = static_cast<uint16_t>(p % PRIMES[i]);

      size_t counter = 0;
      while(true)
         {
         ++counter;

         if(counter > MAX_ATTEMPTS)
            {
            break; // don't try forever, choose a new starting point
            }

         p += modulo;

         if(p.bits() > bits)
            break;

         // Now that p is updated, update the sieve
         for(size_t i = 0; i != sieve.size(); ++i)
            {
            sieve[i] = (sieve[i] + modulo) % PRIMES[i];
            }

         bool passes_sieve = true;
         for(size_t i = 0; passes_sieve && (i != sieve.size()); ++i)
            {
            /*
            In this case, p is a multiple of PRIMES[i]
            */
            if(sieve[i] == 0)
               passes_sieve = false;

            /*
            In this case, 2*p+1 will be a multiple of PRIMES[i]

            So if generating a safe prime, we want to avoid this value
            because 2*p+1 will not be useful. Since the check is cheap to
            do and doesn't seem to affect the overall distribution of the
            generated primes overmuch it's used in all cases.

            See "Safe Prime Generation with a Combined Sieve" M. Wiener
            https://eprint.iacr.org/2003/186.pdf
            */
            if(sieve[i] == (PRIMES[i] - 1) / 2)
               passes_sieve = false;
            }

         if(!passes_sieve)
            continue;

         if(coprime > 0 && gcd(p - 1, coprime) != 1)
            continue;

         if(is_prime(p, rng, prob, true))
            return p;
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

   BigInt q, p;
   for(;;)
      {
      /*
      Generate q == 2 (mod 3)

      Otherwise [q == 1 (mod 3) case], 2*q+1 == 3 (mod 3) and not prime.
      */
      q = random_prime(rng, bits - 1, 1, 2, 3, 8);
      p = (q << 1) + 1;

      if(is_prime(p, rng, 128, true))
         {
         // We did only a weak check before, go back and verify q before returning
         if(is_prime(q, rng, 128, true))
            return p;
         }

      }
   }

}
