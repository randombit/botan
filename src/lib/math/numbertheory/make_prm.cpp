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

namespace {

class Prime_Sieve final
   {
   public:
      Prime_Sieve(const BigInt& init_value) : m_sieve(PRIME_TABLE_SIZE)
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

      Prime_Sieve sieve(p);

      size_t counter = 0;
      while(true)
         {
         ++counter;

         if(counter > MAX_ATTEMPTS)
            {
            break; // don't try forever, choose a new starting point
            }

         p += modulo;

         sieve.step(modulo);

         if(sieve.passes(true) == false)
            continue;

         if(coprime > 1)
            {
            /*
            * Check if gcd(p - 1, coprime) != 1 by computing the inverse. The
            * gcd algorithm is not constant time, but modular inverse is (for
            * odd modulus anyway). This avoids a side channel attack against RSA
            * key generation, though RSA keygen should be using generate_rsa_prime.
            */
            if(inverse_mod(p - 1, coprime).is_zero())
               continue;
            }

         if(p.bits() > bits)
            break;

         if(is_prime(p, rng, prob, true))
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

   while(true)
      {
      BigInt p(keygen_rng, bits);

      // Force lowest and two top bits on
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      Prime_Sieve sieve(p);

      const word step = 2;

      size_t counter = 0;
      while(true)
         {
         ++counter;

         if(counter > MAX_ATTEMPTS)
            {
            break; // don't try forever, choose a new starting point
            }

         p += step;

         sieve.step(step);

         if(sieve.passes() == false)
            continue;

         /*
         * Check if p - 1 and coprime are relatively prime by computing the inverse.
         *
         * We avoid gcd here because that algorithm is not constant time.
         * Modular inverse is (for odd modulus anyway).
         *
         * We earlier verified that coprime argument is odd. Thus the factors of 2
         * in (p - 1) cannot possibly be factors in coprime, so remove them from p - 1.
         * Using an odd modulus allows the const time algorithm to be used.
         *
         * This assumes coprime < p - 1 which is always true for RSA.
         */
         BigInt p1 = p - 1;
         p1 >>= low_zero_bits(p1);
         if(inverse_mod(coprime, p1).is_zero())
            {
            BOTAN_DEBUG_ASSERT(gcd(p1, coprime) > 1);
            continue;
            }

         BOTAN_DEBUG_ASSERT(gcd(p1, coprime) == 1);

         if(p.bits() > bits)
            break;

         if(is_prime(p, prime_test_rng, prob, true))
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
      q = random_prime(rng, bits - 1, 0, 2, 3, 8);
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
