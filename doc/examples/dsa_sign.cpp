#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <memory>

#include <botan/botan.h>
#include <botan/pubkey.h>
#include <botan/dsa.h>
#include <botan/base64.h>
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

      std::ifstream message(argv[2], std::ios::binary);
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

      PK_Signer signer(*dsakey, "EMSA1(SHA-1)");

      DataSource_Stream in(message);
      byte buf[4096] = { 0 };
      while(size_t got = in.read(buf, sizeof(buf)))
         signer.update(buf, got);

      sigfile << base64_encode(signer.signature(rng)) << "\n";
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
