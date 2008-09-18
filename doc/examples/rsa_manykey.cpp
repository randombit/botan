/*
Generate a whole sequence of keys (for benchmarking)
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <memory>

#include <botan/botan.h>
#include <botan/rsa.h>
#include <botan/parsing.h>
using namespace Botan;

int main()
   {
   std::auto_ptr<RandomNumberGenerator> rng(RandomNumberGenerator::make_rng());

   for(u32bit j = 512; j <= 8192; j += 256)
      {
      std::cout << j << "...";

      RSA_PrivateKey key(*rng, j);

      std::ofstream priv(("rsa/" + to_string(j) + ".pem").c_str());
      priv << PKCS8::PEM_encode(key);
      priv.close();

      std::cout << " done" << std::endl;
      }

   return 0;
   }
