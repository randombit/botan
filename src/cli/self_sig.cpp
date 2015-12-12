/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_RSA)

#include <botan/pkcs8.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <fstream>
#include <memory>

using namespace Botan;

namespace {

int self_sig(const std::vector<std::string> &args)
   {
   if(args.size() != 7)
      {
      std::cout << "Usage: " << args[0] << " "
                << "passphrase [CA|user] name country_code organization email"
                << std::endl;
      return 1;
      }

   std::string CA_flag = args[2];
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
      //DL_Group group(rng, DL_Group::DSA_Kosherizer, 2048, 256);


      std::ofstream priv_key("private.pem");
      priv_key << PKCS8::PEM_encode(key, rng, args[1]);

      X509_Cert_Options opts;
      opts.common_name  = args[3];
      opts.country      = args[4];
      opts.organization = args[5];
      opts.email        = args[6];
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

REGISTER_APP(self_sig);

}

#endif // BOTAN_HAS_X509_CERTIFICATES && BOTAN_HAS_RSA
