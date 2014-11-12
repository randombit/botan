#include "apps.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
using namespace Botan;

#include <fstream>
#include <memory>

namespace {

int pkcs10(int argc, char* argv[])
   {
   if(argc != 6)
      {
      std::cout << "Usage: " << argv[0]
                << " passphrase name country_code organization email" << std::endl;
      return 1;
      }

   try
      {
      AutoSeeded_RNG rng;

      RSA_PrivateKey priv_key(rng, 1024);

      std::ofstream key_file("private.pem");
      key_file << PKCS8::PEM_encode(priv_key, rng, argv[1]);

      X509_Cert_Options opts;

      opts.common_name = argv[2];
      opts.country = argv[3];
      opts.organization = argv[4];
      opts.email = argv[5];

      PKCS10_Request req = X509::create_cert_req(opts, priv_key,
                                                 "SHA-256", rng);

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

REGISTER_APP(pkcs10);

}

#endif
