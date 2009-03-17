#include <botan/numthry.h>
#include <botan/auto_rng.h>
#include <botan/botan.h>

using namespace Botan;

#include <iostream>

void test_ressol(const BigInt& p, RandomNumberGenerator& rng)
   {
   std::cout << p << std::endl;

   //   const BigInt p_16 = p / 16;

   int noroot = 0, false_result = 0;

   for(int j = 0; j != 1000; ++j)
      {
      BigInt x = BigInt::random_integer(rng, 0, p);
      //if(x % p_16 == 0)
      //std::cout << "p = " << p << " x = " << x << "\n";

      BigInt sqrt_x = ressol(x, p);

      if(sqrt_x < 0)
         {
         ++noroot;
         continue;
         }

      BigInt check = square(sqrt_x) % p;

      if(check != x % p)
         {
         std::cout << "FAIL "
                   << "x = " << x << "; "
                   << "p = " << p << "; "
                   << "s = " << sqrt_x << "; "
                   << "s^2%p = " << check << "\n";
         ++false_result;
         }
      }
   /*
   std::cout << "nomatch=" << nomatch << " "
             << "noroot=" << noroot << " "
             << "false=" << false_result << "\n";
   */
   }

int main()
   {
   Botan::LibraryInitializer init;
   AutoSeeded_RNG rng;

#if 0
   std::cout << ressol(8, 17) << "\n";
   std::cout << ressol_orig(8, 17) << "\n";
#endif

#if 1
   for(int j = 16; j != 1024; ++j)
      {
      std::cout << "Round " << j << "\n";
      BigInt p = random_prime(rng, j);
      test_ressol(p, rng);
      //printf("%d\n", j);


      }
#endif
   /*
   for(u32bit j = 9; j != PRIME_TABLE_SIZE; ++j)
      {
      std::cout << "PRIME[" << j << "] == " << PRIMES[j] << std::endl;
      //printf("%d - ", PRIMES[j]);
      test_ressol(PRIMES[j], rng);
      //printf("\n");
      }
   */
   }
