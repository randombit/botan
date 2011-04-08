#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <string>
#include <memory>

#include <botan/botan.h>
#include <botan/pubkey.h>
#include <botan/dsa.h>
using namespace Botan;

namespace {

SecureVector<byte> b64_decode(const std::string& in)
   {
   Pipe pipe(new Base64_Decoder);
   pipe.process_msg(in);
   return pipe.read_all();
   }

}

int main(int argc, char* argv[])
   {
   if(argc != 4)
      {
      std::cout << "Usage: " << argv[0]
                << " keyfile messagefile sigfile" << std::endl;
      return 1;
      }


   try {
      Botan::LibraryInitializer init;

      std::ifstream message(argv[2], std::ios::binary);
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

      PK_Verifier ver(*dsakey, "EMSA1(SHA-1)");

      DataSource_Stream in(message);
      byte buf[4096] = { 0 };
      while(size_t got = in.read(buf, sizeof(buf)))
         ver.update(buf, got);

      const bool ok = ver.check_signature(sig);

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
