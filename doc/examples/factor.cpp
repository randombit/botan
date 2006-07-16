/*
   Factor integers using a combination of trial division by small primes,
   and Pollard's Rho algorithm
*/
#include <botan/botan.h>
#include <botan/reducer.h>
#include <botan/numthry.h>
using namespace Botan;

#include <iostream>

BigInt rho(const BigInt& n)
   {
   BigInt x = random_integer(0, n-1);
   BigInt y = x;
   BigInt d = 0;

   Modular_Reducer mod_n(n);

   u32bit i = 1, k = 2;
   while(true)
      {
      i++;

      if(i == 0) // fail
         break;

      x = mod_n.reduce(square(x) - 1);
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

void concat(std::vector<BigInt>& x, const std::vector<BigInt>& y)
   {
   for(u32bit j = 0; j != y.size(); j++)
      x.push_back(y[j]);
   }

std::vector<BigInt> factorize(const BigInt& n)
   {
   std::vector<BigInt> factors;

   if(n <= 1) // no prime factors at all
      return factors;

   if(is_prime(n)) // just n itself
      {
      factors.push_back(n);
      return factors;
      }

   if(n.is_even())
      {
      factors.push_back(2);
      concat(factors, factorize(n / 2));
      return factors;
      }

   BigInt factor = 0;
   while(factor == 0)
      factor = rho(n);

   concat(factors, factorize(factor));
   concat(factors, factorize(n / factor));

   return factors;
   }


int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cerr << "Usage: " << argv[0] << " integer\n";
      return 1;
      }

   try
      {
      LibraryInitializer init;

      BigInt n(argv[1]);
      std::vector<BigInt> factors = factorize(n);

      std::sort(factors.begin(), factors.end());

      std::cout << n << ": ";
      for(u32bit j = 0; j != factors.size(); j++)
         std::cout << factors[j] << " ";
      std::cout << "\n";
      

      }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
