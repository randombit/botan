/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"
#include <botan/numthry.h>

namespace {

int is_prime(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cerr << "Usage: " << argv[0] << " n <prob>" << std::endl;
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
      std::cout << n << " is prime" << std::endl;
      return 0;
      }
   else
      {
      std::cout << n << " is not prime" << std::endl;
      return 1;
      }
   }

REGISTER_APP(is_prime);

}
