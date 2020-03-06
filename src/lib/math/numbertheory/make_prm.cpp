/*
* Prime Generation
* (C) 1999-2007,2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/loadstor.h>
#include <botan/reducer.h>
#include <botan/internal/primality.h>
#include <algorithm>

namespace Botan {

namespace {

class Prime_Sieve final
   {
   public:
      Prime_Sieve(const BigInt& init_value, size_t sieve_size) :
         m_sieve(std::min(sieve_size, PRIME_TABLE_SIZE))
         {
         for(size_t i = 0; i != m_sieve.size(); ++i)
            m_sieve[i] = static_cast<uint16_t>(init_value % PRIMES[i]);
         }

      void step(word increment)
         {
         for(size_t i = 0; i != m_sieve.size(); ++i)
            {
            m_sieve[i] = (m_sieve[i] + increment) % PRIMES[i];
            }
         }

      bool passes(bool check_2p1 = false) const
         {
         for(size_t i = 0; i != m_sieve.size(); ++i)
            {
            /*
            In this case, p is a multiple of PRIMES[i]
            */
            if(m_sieve[i] == 0)
               return false;

            if(check_2p1)
               {
               /*
               In this case, 2*p+1 will be a multiple of PRIMES[i]

               So if potentially generating a safe prime, we want to
               avoid this value because 2*p+1 will certainly not be prime.

               See "Safe Prime Generation with a Combined Sieve" M. Wiener
               https://eprint.iacr.org/2003/186.pdf
               */
               if(m_sieve[i] == (PRIMES[i] - 1) / 2)
                  return false;
               }
            }

         return true;
         }

   private:
      std::vector<uint16_t> m_sieve;
   };

}


/*
* Generate a random prime
*/
BigInt random_prime(RandomNumberGenerator& rng,
                    size_t bits, const BigInt& coprime,
                    size_t equiv, size_t modulo,
                    size_t prob)
   {
   if(bits <= 1)
      {
      throw Invalid_Argument("random_prime: Can't make a prime of " +
                             std::to_string(bits) + " bits");
      }
   if(coprime.is_negative() || (!coprime.is_zero() && coprime.is_even()) || coprime.bits() >= bits)
      {
      throw Invalid_Argument("random_prime: invalid coprime");
      }
   if(modulo == 0)
      {
      throw Invalid_Argument("random_prime: Invalid modulo value");
      }

   equiv %= modulo;

   if(equiv == 0)
      throw Invalid_Argument("random_prime Invalid value for equiv/modulo");

   // Handle small values:

   if(bits <= 16)
      {
      if(equiv != 1 || modulo != 2 || coprime != 0)
         throw Not_Implemented("random_prime equiv/modulo/coprime options not usable for small primes");

      if(bits == 2)
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
      else
         {
         for(;;)
            {
            // This is slightly biased, but for small primes it does not seem to matter
            uint8_t b[4];
            rng.randomize(b, 4);
            const size_t idx = load_le<uint32_t>(b, 0) % PRIME_TABLE_SIZE;
            const uint16_t small_prime = PRIMES[idx];

            if(high_bit(small_prime) == bits)
               return small_prime;
            }
         }
      }

   const size_t MAX_ATTEMPTS = 32*1024;

   const size_t mr_trials = miller_rabin_test_iterations(bits, prob, true);

   while(true)
      {
      BigInt p(rng, bits);

      // Force lowest and two top bits on
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      // Force p to be equal to equiv mod modulo
      p += (modulo - (p % modulo)) + equiv;

      Prime_Sieve sieve(p, bits);

      for(size_t attempt = 0; attempt <= MAX_ATTEMPTS; ++attempt)
         {
         p += modulo;

         sieve.step(modulo);

         // p can be even if modulo is odd, continue on in that case
         if(p.is_even() || sieve.passes(true) == false)
            continue;

         Modular_Reducer mod_p(p);

         if(coprime > 1)
            {
            /*
            First do a single M-R iteration to quickly elimate most non-primes,
            before doing the coprimality check which is expensive
            */
            if(is_miller_rabin_probable_prime(p, mod_p, rng, 1) == false)
               continue;

            /*
            * Check if p - 1 and coprime are relatively prime, using gcd.
            * The gcd computation is const-time
            */
            if(gcd(p - 1, coprime) > 1)
               continue;
            }

         if(p.bits() > bits)
            break;

         if(is_miller_rabin_probable_prime(p, mod_p, rng, mr_trials) == false)
            continue;

         if(prob > 32 && !is_lucas_probable_prime(p, mod_p))
            continue;

         return p;
         }
      }
   }

BigInt generate_rsa_prime(RandomNumberGenerator& keygen_rng,
                          RandomNumberGenerator& prime_test_rng,
                          size_t bits,
                          const BigInt& coprime,
                          size_t prob)
   {
   if(bits < 512)
      throw Invalid_Argument("generate_rsa_prime bits too small");

   /*
   * The restriction on coprime <= 64 bits is arbitrary but generally speaking
   * very large RSA public exponents are a bad idea both for performance and due
   * to attacks on small d.
   */
   if(coprime <= 1 || coprime.is_even() || coprime.bits() > 64)
      throw Invalid_Argument("generate_rsa_prime coprime must be small odd positive integer");

   const size_t MAX_ATTEMPTS = 32*1024;

   const size_t mr_trials = miller_rabin_test_iterations(bits, prob, true);

   while(true)
      {
      BigInt p(keygen_rng, bits);

      // Force high two bits so multiplication always results in expected n bit integer
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      const word step = 2;

      Prime_Sieve sieve(p, bits);

      for(size_t attempt = 0; attempt <= MAX_ATTEMPTS; ++attempt)
         {
         p += step;

         sieve.step(step);

         if(sieve.passes() == false)
            continue;

         Modular_Reducer mod_p(p);

         /*
         * Do a single primality test first before checking coprimality, since
         * currently a single Miller-Rabin test is faster than computing gcd,
         * and this eliminates almost all wasted gcd computations.
         */
         if(is_miller_rabin_probable_prime(p, mod_p, prime_test_rng, 1) == false)
            continue;

         /*
         * Check if p - 1 and coprime are relatively prime.
         */
         if(gcd(p - 1, coprime) > 1)
            continue;

         if(p.bits() > bits)
            break;

         if(is_miller_rabin_probable_prime(p, mod_p, prime_test_rng, mr_trials) == true)
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

   const size_t error_bound = 128;

   BigInt q, p;
   for(;;)
      {
      /*
      Generate q == 2 (mod 3), since otherwise [in the case of q == 1 (mod 3)],
      2*q+1 == 3 (mod 3) and so certainly not prime.
      */
      q = random_prime(rng, bits - 1, 0, 2, 3, error_bound);
      p = (q << 1) + 1;

      if(is_prime(p, rng, error_bound, true))
         {
         return p;
         }
      }
   }

}
