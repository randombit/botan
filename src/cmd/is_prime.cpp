#include "apps.h"
#include <botan/numthry.h>

int is_prime_main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cerr << "Usage: " << argv[0] << " n <prob>\n";
      return 2;
      }

   BigInt n(argv[1]);

   size_t prob = 56;

   if(argc == 3)
      prob = to_u32bit(argv[2]);

   AutoSeeded_RNG rng;

   const bool prime = is_prime(n, rng, prob);

   if(prime)
      {
      std::cout << n << " is prime\n";
      return 0;
      }
   else
      {
      std::cout << n << " is not prime\n";
      return 1;
      }
   }
