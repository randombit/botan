#include <iostream>
#include <fstream>
#include <string>
#include <botan/botan.h>
#include <botan/dsa.h>
#include <botan/rng.h>
using namespace Botan;

#include <memory>

int main(int argc, char* argv[])
   {
   try
      {
      if(argc != 1 && argc != 2)
         {
         std::cout << "Usage: " << argv[0] << " [passphrase]" << std::endl;
         return 1;
         }

      std::ofstream priv("dsapriv.pem");
      std::ofstream pub("dsapub.pem");
      if(!priv || !pub)
         {
         std::cout << "Couldn't write output files" << std::endl;
         return 1;
         }

      Botan::LibraryInitializer init;

      AutoSeeded_RNG rng;

      DL_Group group(rng, DL_Group::DSA_Kosherizer, 2048, 256);

      DSA_PrivateKey key(rng, group);

      pub << X509::PEM_encode(key);
      if(argc == 1)
         priv << PKCS8::PEM_encode(key);
      else
         priv << PKCS8::PEM_encode(key, rng, argv[1]);
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
