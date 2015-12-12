/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/x509_ca.h>
#include <botan/pkcs8.h>

namespace {

int ca(const std::vector<std::string> &args)
   {
   using namespace Botan;

   if(args.size() != 5)
      {
      std::cout << "Usage: " << args[0] << " "
                << "passphrase ca_cert ca_key pkcs10"
                << std::endl;
      return 1;
      }

   const std::string arg_passphrase = args[1];
   const std::string arg_ca_cert    = args[2];
   const std::string arg_ca_key     = args[3];
   const std::string arg_req_file   = args[4];

   try
      {
      AutoSeeded_RNG rng;

      X509_Certificate ca_cert(arg_ca_cert);

      std::unique_ptr<PKCS8_PrivateKey> privkey(
         PKCS8::load_key(arg_ca_key, rng, arg_passphrase)
         );

      X509_CA ca(ca_cert, *privkey, "SHA-256");

      // got a request
      PKCS10_Request req(arg_req_file);

      // you would insert checks here, and perhaps modify the request
      // (this example should be extended to show how)

      // now sign the request
      auto now = std::chrono::system_clock::now();

      X509_Time start_time(now);

      typedef std::chrono::duration<int, std::ratio<31556926>> years;

      X509_Time end_time(now + years(1));

      X509_Certificate new_cert = ca.sign_request(req, rng,
                                                  start_time, end_time);

      // send the new cert back to the requestor
      std::cout << new_cert.PEM_encode();
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }

REGISTER_APP(ca);

}

#endif
