/*
Generate a 1024 bit DSA key and put it into a file. The public key format is
that specified by X.509, while the private key format is PKCS #8.

The domain parameters are the ones specified as the Java default DSA
parameters. There is nothing special about these, it's just the only 1024-bit
DSA parameter set that's included in Botan at the time of this writing. The
application always reads/writes all of the domain parameters to/from the file,
so a new set could be used without any problems. We could generate a new set
for each key, or read a set of DSA params from a file and use those, but they
mostly seem like needless complications.

Written by Jack Lloyd (lloyd@randombit.net), August 5, 2002
   Updated to use X.509 and PKCS #8 formats, October 21, 2002

This file is in the public domain
*/

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
   if(argc != 1 && argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " [passphrase]" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::ofstream priv("dsapriv.pem");
   std::ofstream pub("dsapub.pem");
   if(!priv || !pub)
      {
      std::cout << "Couldn't write output files" << std::endl;
      return 1;
      }

   try
      {
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
