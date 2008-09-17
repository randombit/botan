#include <botan/botan.h>
#include <botan/ec.h>

#include <memory>
#include <iostream>

using namespace Botan;

int main()
   {
   std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

   EC_Domain_Params params = get_EC_Dom_Pars_by_oid("1.3.132.8");

   std::cout << params.get_curve().get_p() << "\n";
   std::cout << params.get_order() << "\n";

   ECDSA_PrivateKey ecdsa(*rng, params);

   }
