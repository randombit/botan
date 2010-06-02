/*
* (C) 2009-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*
* Factor integers using a combination of trial division by small
* primes, and Pollard's Rho algorithm
*/

#include <botan/botan.h>
#include <botan/reducer.h>
#include <botan/numthry.h>
using namespace Botan;

#include <algorithm>
#include <iostream>
#include <iterator>

namespace {

/*
* Pollard's Rho algorithm, as described in the MIT algorithms book. We
* use (x^2+x) mod n instead of (x*2-1) mod n as the random function,
* it _seems_ to lead to faster factorization for the values I tried.
*/
BigInt rho(const BigInt& n, RandomNumberGenerator& rng)
   {
   BigInt x = BigInt::random_integer(rng, 0, n-1);
   BigInt y = x;
   BigInt d = 0;

   Modular_Reducer mod_n(n);

   u32bit i = 1, k = 2;
   while(true)
      {
      i++;

      if(i == 0) // overflow, bail out
         break;

      x = mod_n.multiply((x + 1), x);

      d = gcd(y - x, n);
      if(d != 1 && d != n)
         return d;

      if(i == k)
         {
         y = x;
         k = 2*k;
         }
      }
   return 0;
   }

// Remove (and return) any small (< 2^16) factors
std::vector<BigInt> remove_small_factors(BigInt& n)
   {
   std::vector<BigInt> factors;

   while(n.is_even())
      {
      factors.push_back(2);
      n /= 2;
      }

   for(u32bit j = 0; j != PRIME_TABLE_SIZE; j++)
      {
      if(n < PRIMES[j])
         break;

      BigInt x = gcd(n, PRIMES[j]);

      if(x != 1)
         {
         n /= x;

         u32bit occurs = 0;
         while(x != 1)
            {
            x /= PRIMES[j];
            occurs++;
            }

         for(u32bit k = 0; k != occurs; k++)
            factors.push_back(PRIMES[j]);
         }
      }

   return factors;
   }

std::vector<BigInt> factorize(const BigInt& n_in,
                              RandomNumberGenerator& rng)
   {
   BigInt n = n_in;
   std::vector<BigInt> factors = remove_small_factors(n);

   while(n != 1)
      {
      if(check_prime(n, rng))
         {
         factors.push_back(n);
         break;
         }

      BigInt a_factor = 0;
      while(a_factor == 0)
         a_factor = rho(n, rng);

      std::vector<BigInt> rho_factored = factorize(a_factor, rng);
      for(u32bit j = 0; j != rho_factored.size(); j++)
         factors.push_back(rho_factored[j]);

      n /= a_factor;
      }
   return factors;
   }

}

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cerr << "Usage: " << argv[0] << " integer\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   try
      {
      BigInt n(argv[1]);

      AutoSeeded_RNG rng;

      std::vector<BigInt> factors = factorize(n, rng);
      std::sort(factors.begin(), factors.end());

      std::cout << n << ": ";
      std::copy(factors.begin(),
                factors.end(),
                std::ostream_iterator<BigInt>(std::cout, " "));
      std::cout << "\n";
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
