#include <botan/botan.h>
#include <botan/ecdsa.h>

using namespace Botan;

int main()
   {
   std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

   EC_Domain_Params params = 

   ECDSA_PrivateKey ecdsa(rng, 

   }
