/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)

#include <botan/numthry.h>

#include <algorithm>
#include <iostream>

namespace {

int prime(const std::vector<std::string> &args)
   {
   if(args.size() < 2 || args.size() > 3)
      {
      std::cout << "Usage: " << args[0] << " bits [count]" << std::endl;
      return 1;
      }

   AutoSeeded_RNG rng;
   const size_t bits = to_u32bit(args[1]);
   const size_t cnt = args.size() >= 3 ? to_u32bit(args[2]) : 1;

   for(size_t i = 0; i != cnt; ++i)
      {
      const BigInt p = random_prime(rng, bits);
      std::cout << p << std::endl;

      if(p.bits() != bits)
         {
         std::cout << "Result not exactly requested bit size, got " << p.bits() << std::endl;
         }
      }

   return 0;
   }

}

REGISTER_APP(prime);

#endif
