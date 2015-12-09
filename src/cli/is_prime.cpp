/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)

#include <botan/numthry.h>

namespace {

int is_prime(const std::vector<std::string> &args)
   {
   if(args.size() != 2 && args.size() != 3)
      {
      std::cerr << "Usage: " << args[0] << " n <prob>" << std::endl;
      return 2;
      }

   BigInt n(args[1]);

   size_t prob = 56;

   if(args.size() == 3)
      prob = to_u32bit(args[2]);

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

#endif // BOTAN_HAS_NUMBERTHEORY
