/*
* Random Number Generator
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
#include <botan/hmac_rng.h>
#include <botan/lookup.h>

namespace Botan {

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
   std::unique_ptr<MessageAuthenticationCode> h1(make_message_auth("HMAC(SHA-512"));
   std::unique_ptr<MessageAuthenticationCode> h2(h1->clone());
   std::unique_ptr<RandomNumberGenerator> rng(new HMAC_RNG(h1.release(), h2.release()));

   rng->reseed(256);

   return rng.release();
   }

}
