/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_DSA)

#include <botan/dsa.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/base64.h>
#include <fstream>

namespace {

int dsa_sign(const std::vector<std::string> &args)
   {
   using namespace Botan;

   const std::string SUFFIX = ".sig";

   if(args.size() != 4)
      {
      std::cout << "Usage: " << args[0] << " keyfile messagefile passphrase"
                << std::endl;
      return 1;
      }

   try {
      std::string passphrase(args[3]);

      std::ifstream message(args[2], std::ios::binary);
      if(!message)
         {
         std::cout << "Couldn't read the message file." << std::endl;
         return 1;
         }

      std::string outfile = args[2] + SUFFIX;
      std::ofstream sigfile(outfile);
      if(!sigfile)
         {
         std::cout << "Couldn't write the signature to "
                   << outfile << std::endl;
         return 1;
         }

      AutoSeeded_RNG rng;

      std::unique_ptr<PKCS8_PrivateKey> key(
         PKCS8::load_key(args[1], rng, passphrase)
         );

      DSA_PrivateKey* dsakey = dynamic_cast<DSA_PrivateKey*>(key.get());

      if(!dsakey)
         {
         std::cout << "The loaded key is not a DSA key!" << std::endl;
         return 1;
         }

      PK_Signer signer(*dsakey, "EMSA1(SHA-1)");

      DataSource_Stream in(message);
      byte buf[4096] = { 0 };
      while(size_t got = in.read(buf, sizeof(buf)))
         signer.update(buf, got);

      sigfile << base64_encode(signer.signature(rng)) << std::endl;
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }

REGISTER_APP(dsa_sign);

}

#endif
