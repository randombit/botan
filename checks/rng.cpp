
#include "common.h"

using namespace Botan;

RandomNumberGenerator& global_rng()
   {
   static RandomNumberGenerator* rng = 0;

   if(!rng)
      rng = make_rng();

   return *rng;
   }
