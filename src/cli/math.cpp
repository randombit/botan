/*
* (C) 2009,2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)

#include <botan/reducer.h>
#include <botan/numthry.h>
#include <iterator>

namespace Botan_CLI {

class Gen_Prime final : public Command
   {
   public:
      Gen_Prime() : Command("gen_prime --count=1 bits") {}

      void go() override
         {
         const size_t bits = get_arg_sz("bits");
         const size_t cnt = get_arg_sz("count");

         for(size_t i = 0; i != cnt; ++i)
            {
            const Botan::BigInt p = Botan::random_prime(rng(), bits);
            output() << p << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("gen_prime", Gen_Prime);

class Is_Prime final : public Command
   {
   public:
      Is_Prime() : Command("is_prime --prob=56 n") {}

      void go() override
         {
         Botan::BigInt n(get_arg("n"));
         const size_t prob = get_arg_sz("prob");
         const bool prime = Botan::is_prime(n, rng(), prob);

         output() << n << " is " << (prime ? "probably prime" : "composite") << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("is_prime", Is_Prime);

/*
* Factor integers using a combination of trial division by small
* primes, and Pollard's Rho algorithm
*/
class Factor final : public Command
   {
   public:
      Factor() : Command("factor n") {}

      void go() override
         {
         Botan::BigInt n(get_arg("n"));

         std::vector<Botan::BigInt> factors = factorize(n, rng());
         std::sort(factors.begin(), factors.end());

         output() << n << ": ";
         std::copy(factors.begin(), factors.end(), std::ostream_iterator<Botan::BigInt>(output(), " "));
         output() << std::endl;
         }

   private:

      std::vector<Botan::BigInt> factorize(const Botan::BigInt& n_in,
                                           Botan::RandomNumberGenerator& rng)
         {
         Botan::BigInt n = n_in;
         std::vector<Botan::BigInt> factors = remove_small_factors(n);

         while(n != 1)
            {
            if(Botan::is_prime(n, rng))
               {
               factors.push_back(n);
               break;
               }

            Botan::BigInt a_factor = 0;
            while(a_factor == 0)
               {
               a_factor = rho(n, rng);
               }

            std::vector<Botan::BigInt> rho_factored = factorize(a_factor, rng);
            for(size_t j = 0; j != rho_factored.size(); j++)
               {
               factors.push_back(rho_factored[j]);
               }

            n /= a_factor;
            }

         return factors;
         }

      /*
      * Pollard's Rho algorithm, as described in the MIT algorithms book. We
      * use (x^2+x) mod n instead of (x*2-1) mod n as the random function,
      * it _seems_ to lead to faster factorization for the values I tried.
      */
      Botan::BigInt rho(const Botan::BigInt& n, Botan::RandomNumberGenerator& rng)
         {
         Botan::BigInt x = Botan::BigInt::random_integer(rng, 0, n - 1);
         Botan::BigInt y = x;
         Botan::BigInt d = 0;

         Botan::Modular_Reducer mod_n(n);

         size_t i = 1, k = 2;
         while(true)
            {
            i++;

            if(i == 0) // overflow, bail out
               {
               break;
               }

            x = mod_n.multiply((x + 1), x);

            d = Botan::gcd(y - x, n);
            if(d != 1 && d != n)
               {
               return d;
               }

            if(i == k)
               {
               y = x;
               k = 2 * k;
               }
            }
         return 0;
         }

      // Remove (and return) any small (< 2^16) factors
      std::vector<Botan::BigInt> remove_small_factors(Botan::BigInt& n)
         {
         std::vector<Botan::BigInt> factors;

         while(n.is_even())
            {
            factors.push_back(2);
            n /= 2;
            }

         for(size_t j = 0; j != Botan::PRIME_TABLE_SIZE; j++)
            {
            uint16_t prime = Botan::PRIMES[j];
            if(n < prime)
               {
               break;
               }

            Botan::BigInt x = Botan::gcd(n, prime);

            if(x != 1)
               {
               n /= x;

               while(x != 1)
                  {
                  x /= prime;
                  factors.push_back(prime);
                  }
               }
            }

         return factors;
         }
   };

BOTAN_REGISTER_COMMAND("factor", Factor);

}

#endif
