/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_DSA)

#include <fstream>
#include <botan/pubkey.h>
#include <botan/dsa.h>
#include <botan/base64.h>

using namespace Botan;

namespace {

int dsa_verify(const std::vector<std::string> &args)
   {
   if(args.size() != 4)
      {
      std::cout << "Usage: " << args[0] << " "
                << "keyfile messagefile sigfile"
                << std::endl;
      return 1;
      }


   try {
      std::ifstream message(args[2], std::ios::binary);
      if(!message)
         {
         std::cout << "Couldn't read the message file." << std::endl;
         return 1;
         }

      std::ifstream sigfile(args[3]);
      if(!sigfile)
         {
         std::cout << "Couldn't read the signature file." << std::endl;
         return 1;
         }

      std::string sigstr;
      getline(sigfile, sigstr);

      std::unique_ptr<X509_PublicKey> key(X509::load_key(args[1]));
      DSA_PublicKey* dsakey = dynamic_cast<DSA_PublicKey*>(key.get());

      if(!dsakey)
         {
         std::cout << "The loaded key is not a DSA key!" << std::endl;
         return 1;
         }

      secure_vector<byte> sig = base64_decode(sigstr);

      PK_Verifier ver(*dsakey, "EMSA1(SHA-1)");

      DataSource_Stream in(message);
      byte buf[4096] = { 0 };
      while(size_t got = in.read(buf, sizeof(buf)))
         ver.update(buf, got);

      const bool ok = ver.check_signature(sig);

      if(ok)
         {
         std::cout << "Signature verified" << std::endl;
         return 0;
         }
      else
         {
         std::cout << "Signature did NOT verify" << std::endl;
         return 1;
         }
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 2;
      }
   }

REGISTER_APP(dsa_verify);

}

#endif

