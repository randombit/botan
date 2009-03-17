/*
Decrypt an encrypted DSA private key. Then use that key to sign a message.

Written by Jack Lloyd (lloyd@randombit.net), August 5, 2002
   Updated to use X.509 and PKCS #8 format keys, October 21, 2002

This file is in the public domain
*/

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <memory>

#include <botan/botan.h>
#include <botan/look_pk.h>
#include <botan/dsa.h>
using namespace Botan;

const std::string SUFFIX = ".sig";

int main(int argc, char* argv[])
   {
   if(argc != 4)
      {
      std::cout << "Usage: " << argv[0] << " keyfile messagefile passphrase"
                << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   try {
      std::string passphrase(argv[3]);

      std::ifstream message(argv[2]);
      if(!message)
         {
         std::cout << "Couldn't read the message file." << std::endl;
         return 1;
         }

      std::string outfile = argv[2] + SUFFIX;
      std::ofstream sigfile(outfile.c_str());
      if(!sigfile)
         {
         std::cout << "Couldn't write the signature to "
                   << outfile << std::endl;
         return 1;
         }

      AutoSeeded_RNG rng;

      std::auto_ptr<PKCS8_PrivateKey> key(
         PKCS8::load_key(argv[1], rng, passphrase)
         );

      DSA_PrivateKey* dsakey = dynamic_cast<DSA_PrivateKey*>(key.get());

      if(!dsakey)
         {
         std::cout << "The loaded key is not a DSA key!\n";
         return 1;
         }

      PK_Signer signer(*dsakey, get_emsa("EMSA1(SHA-1)"));

      DataSource_Stream in(message);
      byte buf[4096] = { 0 };
      while(u32bit got = in.read(buf, sizeof(buf)))
         signer.update(buf, got);

      Pipe pipe(new Base64_Encoder);
      pipe.process_msg(signer.signature(rng));
      sigfile << pipe.read_all_as_string() << std::endl;
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
