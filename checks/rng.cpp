
#include "common.h"
#include <botan/x931_rng.h>
#include <botan/randpool.h>
#include <botan/es_dev.h>
#include <botan/parsing.h>

using namespace Botan;

RandomNumberGenerator& global_rng()
   {
   static RandomNumberGenerator* rng = 0;

   if(!rng)
      {
      rng = new ANSI_X931_RNG("AES-256", new Randpool("AES-256", "HMAC(SHA-256)"));

      Device_EntropySource dev(split_on("/dev/random:/dev/srandom:/dev/urandom", ':'));

      rng->add_entropy(dev);
      }

   return *rng;
   }
