/*
* Random Number Generator
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
#include <botan/hmac_rng.h>
#include <botan/algo_registry.h>

namespace Botan {

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
   std::unique_ptr<RandomNumberGenerator> rng(
      new HMAC_RNG(make_a<MessageAuthenticationCode>("HMAC(SHA-512)"),
                   make_a<MessageAuthenticationCode>("HMAC(SHA-256)"))
      );

   rng->reseed(256);

   return rng.release();
   }

}
