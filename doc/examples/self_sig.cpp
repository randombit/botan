#include <botan/botan.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
using namespace Botan;

#include <iostream>
#include <fstream>
#include <memory>

int main(int argc, char* argv[])
   {
   if(argc != 7)
      {
      std::cout << "Usage: " << argv[0]
                << " passphrase [CA|user] name country_code organization email"
                << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::string CA_flag = argv[2];
   bool do_CA = false;

   if(CA_flag == "CA") do_CA = true;
   else if(CA_flag == "user") do_CA = false;
   else
      {
      std::cout << "Bad flag for CA/user switch: " << CA_flag << std::endl;
      return 1;
      }

   try
      {
      AutoSeeded_RNG rng;

      RSA_PrivateKey key(rng, 2048);

      std::ofstream priv_key("private.pem");
      priv_key << PKCS8::PEM_encode(key, rng, argv[1]);

      X509_Cert_Options opts;

      opts.common_name = argv[3];
      opts.country = argv[4];
      opts.organization = argv[5];
      opts.email = argv[6];
      /* Fill in other values of opts here */

      //opts.xmpp = "lloyd@randombit.net";

      if(do_CA)
         opts.CA_key();

      X509_Certificate cert =
         X509::create_self_signed_cert(opts, key, "SHA-256", rng);

      std::ofstream cert_file("cert.pem");
      cert_file << cert.PEM_encode();
   }
   catch(std::exception& e)
      {
      std::cout << "Exception: " << e.what() << std::endl;
      return 1;
      }

   return 0;
   }
