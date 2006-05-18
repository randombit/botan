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
#include <botan/botan.h>
#include <botan/rsa.h>
using namespace Botan;

int main(int argc, char* argv[])
   {
   if(argc != 3)
      {
      std::cout << "Usage: " << argv[0] << " bitsize passphrase" << std::endl;
      return 1;
      }

   u32bit bits = std::atoi(argv[1]);
   if(bits < 512 || bits > 4096)
      {
      std::cout << "Invalid argument for bitsize" << std::endl;
      return 1;
      }

   std::string passphrase(argv[2]);

   std::ofstream pub("rsapub.pem");
   std::ofstream priv("rsapriv.pem");
   if(!priv || !pub)
      {
      std::cout << "Couldn't write output files" << std::endl;
      return 1;
      }

   try {
      LibraryInitializer init;
      RSA_PrivateKey key(bits);
      pub << X509::PEM_encode(key);
      priv << PKCS8::PEM_encode(key, passphrase);
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
