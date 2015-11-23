/*
* Random Number Generator
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
#include <botan/hmac_rng.h>
#include <botan/entropy_src.h>

namespace Botan {

void RandomNumberGenerator::reseed(size_t bits_to_collect)
   {
   this->reseed_with_sources(Entropy_Sources::global_sources(),
                             bits_to_collect,
                             BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);
   }

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
   std::unique_ptr<MessageAuthenticationCode> h1(MessageAuthenticationCode::create("HMAC(SHA-512)"));
   std::unique_ptr<MessageAuthenticationCode> h2(MessageAuthenticationCode::create("HMAC(SHA-512)"));

   if(!h1 || !h2)
      throw Algorithm_Not_Found("HMAC_RNG HMACs");
   std::unique_ptr<RandomNumberGenerator> rng(new HMAC_RNG(h1.release(), h2.release()));

   rng->reseed(256);

   return rng.release();
   }

}
