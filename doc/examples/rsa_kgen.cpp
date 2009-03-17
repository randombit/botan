/*
Generate an RSA key of a specified bitlength, and put it into a pair of key
files. One is the public key in X.509 format (PEM encoded), the private key is
in PKCS #8 format (also PEM encoded).

Written by Jack Lloyd (lloyd@randombit.net), June 2-3, 2002
  Updated to use X.509 and PKCS #8 on October 21, 2002

This file is in the public domain
*/

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

   u32bit bits = std::atoi(argv[1]);
   if(bits < 1024 || bits > 4096)
      {
      std::cout << "Invalid argument for bitsize" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::ofstream pub("rsapub.pem");
   std::ofstream priv("rsapriv.pem");
   if(!priv || !pub)
      {
      std::cout << "Couldn't write output files" << std::endl;
      return 1;
      }

   try
      {
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
