#include <botan/botan.h>
#include <botan/ecdsa.h>

#include <memory>
#include <iostream>

using namespace Botan;

int main()
   {
   try
      {
      std::auto_ptr<RandomNumberGenerator> rng(
         RandomNumberGenerator::make_rng());

      EC_Domain_Params params = get_EC_Dom_Pars_by_oid("1.3.132.0.8");

      std::cout << params.get_curve().get_p() << "\n";
      std::cout << params.get_order() << "\n";

      ECDSA_PrivateKey ecdsa(*rng, params);

      std::cout << X509::PEM_encode(ecdsa);
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << "\n";
      }
   }
