/*
Generate a 1024 bit RSA key, and then create a PKCS #10 certificate request for
that key. The private key will be stored as an encrypted PKCS #8 object, and
stored in another file.

Written by Jack Lloyd (lloyd@randombit.net), April 7, 2003

This file is in the public domain
*/
#include <botan/init.h>
#include <botan/auto_rng.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
using namespace Botan;

#include <iostream>
#include <fstream>
#include <memory>

int main(int argc, char* argv[])
   {
   if(argc != 6)
      {
      std::cout << "Usage: " << argv[0] <<
         " passphrase name country_code organization email" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   try
      {
      AutoSeeded_RNG rng;

      RSA_PrivateKey priv_key(rng, 1024);
      // If you want a DSA key instead of RSA, comment out the above line and
      // uncomment this one:
      //DSA_PrivateKey priv_key(DL_Group("dsa/jce/1024"));

      std::ofstream key_file("private.pem");
      key_file << PKCS8::PEM_encode(priv_key, rng, argv[1]);

      X509_Cert_Options opts;

      opts.common_name = argv[2];
      opts.country = argv[3];
      opts.organization = argv[4];
      opts.email = argv[5];

      /* Some hard-coded options, just to give you an idea of what's there */
      opts.challenge = "a fixed challenge passphrase";
      opts.locality = "Baltimore";
      opts.state = "MD";
      opts.org_unit = "Testing";
      opts.add_ex_constraint("PKIX.ClientAuth");
      opts.add_ex_constraint("PKIX.IPsecUser");
      opts.add_ex_constraint("PKIX.EmailProtection");

      opts.xmpp = "someid@xmpp.org";

      PKCS10_Request req = X509::create_cert_req(opts, priv_key, rng);

      std::ofstream req_file("req.pem");
      req_file << req.PEM_encode();
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
