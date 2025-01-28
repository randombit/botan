/*
* Prime Generation
* (C) 1999-2007,2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/primality.h>

#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <algorithm>

namespace Botan {

namespace {

class Prime_Sieve final {
   public:
      Prime_Sieve(const BigInt& init_value, size_t sieve_size, word step, bool check_2p1) :
            m_sieve(std::min(sieve_size, PRIME_TABLE_SIZE)), m_step(step), m_check_2p1(check_2p1) {
         for(size_t i = 0; i != m_sieve.size(); ++i) {
            m_sieve[i] = init_value % PRIMES[i];
         }
      }

      size_t sieve_size() const { return m_sieve.size(); }

      bool check_2p1() const { return m_check_2p1; }

      bool next() {
         auto passes = CT::Mask<word>::set();
         for(size_t i = 0; i != m_sieve.size(); ++i) {
            m_sieve[i] = (m_sieve[i] + m_step) % PRIMES[i];

            // If m_sieve[i] == 0 then val % p == 0 -> not prime
            passes &= CT::Mask<word>::expand(m_sieve[i]);

            if(this->check_2p1()) {
               /*
               If v % p == (p-1)/2 then 2*v+1 == 0 (mod p)

               So if potentially generating a safe prime, we want to
               avoid this value because 2*v+1 will certainly not be prime.

               See "Safe Prime Generation with a Combined Sieve" M. Wiener
               https://eprint.iacr.org/2003/186.pdf
               */
               passes &= ~CT::Mask<word>::is_equal(m_sieve[i], (PRIMES[i] - 1) / 2);
            }
         }

         return passes.as_bool();
      }

   private:
      std::vector<word> m_sieve;
      const word m_step;
      const bool m_check_2p1;
};

#if defined(BOTAN_ENABLE_DEBUG_ASSERTS)

bool no_small_multiples(const BigInt& v, const Prime_Sieve& sieve) {
   const size_t sieve_size = sieve.sieve_size();
   const bool check_2p1 = sieve.check_2p1();

   if(v.is_even())
      return false;

   const BigInt v_x2_p1 = 2 * v + 1;

   for(size_t i = 0; i != sieve_size; ++i) {
      if((v % PRIMES[i]) == 0)
         return false;

      if(check_2p1) {
         if(v_x2_p1 % PRIMES[i] == 0)
            return false;
      }
   }

   return true;
}

#endif

}  // namespace

/*
* Generate a random prime
*/
BigInt random_prime(
   RandomNumberGenerator& rng, size_t bits, const BigInt& coprime, size_t equiv, size_t modulo, size_t prob) {
   if(bits <= 1) {
      throw Invalid_Argument("random_prime: Can't make a prime of " + std::to_string(bits) + " bits");
   }
   if(coprime.is_negative() || (!coprime.is_zero() && coprime.is_even()) || coprime.bits() >= bits) {
      throw Invalid_Argument("random_prime: invalid coprime");
   }
   if(modulo == 0 || modulo >= 100000) {
      throw Invalid_Argument("random_prime: Invalid modulo value");
   }

   equiv %= modulo;

   if(equiv == 0) {
      throw Invalid_Argument("random_prime Invalid value for equiv/modulo");
   }

   // Handle small values:

   if(bits <= 16) {
      if(equiv != 1 || modulo != 2 || coprime != 0) {
         throw Not_Implemented("random_prime equiv/modulo/coprime options not usable for small primes");
      }

      if(bits == 2) {
         return BigInt::from_word(((rng.next_byte() % 2) ? 2 : 3));
      } else if(bits == 3) {
         return BigInt::from_word(((rng.next_byte() % 2) ? 5 : 7));
      } else if(bits == 4) {
         return BigInt::from_word(((rng.next_byte() % 2) ? 11 : 13));
      } else {
         for(;;) {
            // This is slightly biased, but for small primes it does not seem to matter
            uint8_t b[4] = {0};
            rng.randomize(b, 4);
            const size_t idx = load_le<uint32_t>(b, 0) % PRIME_TABLE_SIZE;
            const uint16_t small_prime = PRIMES[idx];

            if(high_bit(small_prime) == bits) {
               return BigInt::from_word(small_prime);
            }
         }
      }
   }

   const size_t MAX_ATTEMPTS = 32 * 1024;

   const size_t mr_trials = miller_rabin_test_iterations(bits, prob, true);

   while(true) {
      BigInt p(rng, bits);

      // Force lowest and two top bits on
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(0);

      // Force p to be equal to equiv mod modulo
      p += (modulo - (p % modulo)) + equiv;

      Prime_Sieve sieve(p, bits, modulo, true);

      for(size_t attempt = 0; attempt <= MAX_ATTEMPTS; ++attempt) {
         p += modulo;

         if(!sieve.next()) {
            continue;
         }

         // here p can be even if modulo is odd, continue on in that case
         if(p.is_even()) {
            continue;
         }

         BOTAN_DEBUG_ASSERT(no_small_multiples(p, sieve));

         auto mod_p = Modular_Reducer::for_secret_modulus(p);

         if(coprime > 1) {
            /*
            First do a single M-R iteration to quickly elimate most non-primes,
            before doing the coprimality check which is expensive
            */
            if(is_miller_rabin_probable_prime(p, mod_p, rng, 1) == false) {
               continue;
            }

            /*
            * Check if p - 1 and coprime are relatively prime, using gcd.
            * The gcd computation is const-time
            */
            if(gcd(p - 1, coprime) > 1) {
               continue;
            }
         }

         if(p.bits() > bits) {
            break;
         }

         if(is_miller_rabin_probable_prime(p, mod_p, rng, mr_trials) == false) {
            continue;
         }

         if(prob > 32 && !is_lucas_probable_prime(p, mod_p)) {
            continue;
         }

         return p;
      }
   }
}

BigInt generate_rsa_prime(RandomNumberGenerator& keygen_rng,
                          RandomNumberGenerator& prime_test_rng,
                          size_t bits,
                          const BigInt& coprime,
                          size_t prob) {
   if(bits < 512) {
      throw Invalid_Argument("generate_rsa_prime bits too small");
   }

   /*
   * The restriction on coprime <= 64 bits is arbitrary but generally speaking
   * very large RSA public exponents are a bad idea both for performance and due
   * to attacks on small d.
   */
   if(coprime <= 1 || coprime.is_even() || coprime.bits() > 64) {
      throw Invalid_Argument("generate_rsa_prime coprime must be small odd positive integer");
   }

   const size_t MAX_ATTEMPTS = 32 * 1024;

   const size_t mr_trials = miller_rabin_test_iterations(bits, prob, true);

   while(true) {
      BigInt p(keygen_rng, bits);

      /*
      Force high two bits so multiplication always results in expected n bit integer

      Force the two low bits, and step by 4, so the generated prime is always == 3 (mod 4).
      This way when we perform the inversion modulo phi(n) it is always of the form 2*o
      with o odd, which allows a fastpath and avoids leaking any information about the
      structure of the prime.
      */
      p.set_bit(bits - 1);
      p.set_bit(bits - 2);
      p.set_bit(1);
      p.set_bit(0);

      const word step = 4;

      Prime_Sieve sieve(p, bits, step, false);

      for(size_t attempt = 0; attempt <= MAX_ATTEMPTS; ++attempt) {
         p += step;

         if(!sieve.next()) {
            continue;
         }

         BOTAN_DEBUG_ASSERT(no_small_multiples(p, sieve));

         auto mod_p = Modular_Reducer::for_secret_modulus(p);

         /*
         * Do a single primality test first before checking coprimality, since
         * currently a single Miller-Rabin test is faster than computing gcd,
         * and this eliminates almost all wasted gcd computations.
         */
         if(is_miller_rabin_probable_prime(p, mod_p, prime_test_rng, 1) == false) {
            continue;
         }

         /*
         * Check if p - 1 and coprime are relatively prime.
         */
         if(gcd(p - 1, coprime) > 1) {
            continue;
         }

         if(p.bits() > bits) {
            break;
         }

         if(is_miller_rabin_probable_prime(p, mod_p, prime_test_rng, mr_trials) == true) {
            return p;
         }
      }
   }
}

/*
* Generate a random safe prime
*/
BigInt random_safe_prime(RandomNumberGenerator& rng, size_t bits) {
   if(bits <= 64) {
      throw Invalid_Argument("random_safe_prime: Can't make a prime of " + std::to_string(bits) + " bits");
   }

   const size_t error_bound = 128;

   BigInt q, p;
   for(;;) {
      /*
      Generate q == 2 (mod 3), since otherwise [in the case of q == 1 (mod 3)],
      2*q+1 == 3 (mod 3) and so certainly not prime.
      */
      q = random_prime(rng, bits - 1, BigInt::zero(), 2, 3, error_bound);
      p = (q << 1) + 1;

      if(is_prime(p, rng, error_bound, true)) {
         return p;
      }
   }
}

}  // namespace Botan
