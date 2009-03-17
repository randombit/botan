/*
Grab an DSA public key from the file given as an argument, grab a signature
from another file, and verify the message (which, suprise, is also in a file).

The signature format isn't particularly standard, but it's not bad. It's simply
the IEEE 1363 signature format, encoded into base64 with a trailing newline

Written by Jack Lloyd (lloyd@randombit.net), August 5, 2002
   Updated to use X.509 format keys, October 21, 2002

This file is in the public domain
*/

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <string>
#include <memory>

#include <botan/botan.h>
#include <botan/look_pk.h>
#include <botan/dsa.h>
using namespace Botan;

SecureVector<byte> b64_decode(const std::string& in)
   {
   Pipe pipe(new Base64_Decoder);
   pipe.process_msg(in);
   return pipe.read_all();
   }

int main(int argc, char* argv[])
   {
   if(argc != 4)
      {
      std::cout << "Usage: " << argv[0]
                << " keyfile messagefile sigfile" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::ifstream message(argv[2]);
   if(!message)
      {
      std::cout << "Couldn't read the message file." << std::endl;
      return 1;
      }

   std::ifstream sigfile(argv[3]);
   if(!sigfile)
      {
      std::cout << "Couldn't read the signature file." << std::endl;
      return 1;
      }

   try {
      std::string sigstr;
      getline(sigfile, sigstr);

      std::auto_ptr<X509_PublicKey> key(X509::load_key(argv[1]));
      DSA_PublicKey* dsakey = dynamic_cast<DSA_PublicKey*>(key.get());
      if(!dsakey)
         {
         std::cout << "The loaded key is not a DSA key!\n";
         return 1;
         }

      SecureVector<byte> sig = b64_decode(sigstr);

      std::auto_ptr<PK_Verifier> ver(get_pk_verifier(*dsakey, "EMSA1(SHA-1)"));

      DataSource_Stream in(message);
      byte buf[4096] = { 0 };
      while(u32bit got = in.read(buf, sizeof(buf)))
         ver->update(buf, got);

      bool ok = ver->check_signature(sig);

      if(ok)
         std::cout << "Signature verified\n";
      else
         std::cout << "Signature did NOT verify\n";
   }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
