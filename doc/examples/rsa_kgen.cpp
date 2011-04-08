#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <memory>

#include <botan/botan.h>
#include <botan/rsa.h>
using namespace Botan;

int main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cout << "Usage: " << argv[0] << " bitsize [passphrase]"
                << std::endl;
      return 1;
      }

   const size_t bits = std::atoi(argv[1]);
   if(bits < 1024 || bits > 16384)
      {
      std::cout << "Invalid argument for bitsize" << std::endl;
      return 1;
      }

   try
      {
      Botan::LibraryInitializer init;

      std::ofstream pub("rsapub.pem");
      std::ofstream priv("rsapriv.pem");
      if(!priv || !pub)
         {
         std::cout << "Couldn't write output files" << std::endl;
         return 1;
         }

      AutoSeeded_RNG rng;

      RSA_PrivateKey key(rng, bits);
      pub << X509::PEM_encode(key);

      if(argc == 2)
         priv << PKCS8::PEM_encode(key);
      else
         priv << PKCS8::PEM_encode(key, rng, argv[2]);
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
