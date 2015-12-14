/*
* Simple example of a certificate validation
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/x509path.h>

namespace {

int cert_verify(const std::vector<std::string> &args)
   {
   using namespace Botan;

   if(args.size() < 3)
      {
      std::cout << "Usage: " << args[0] << " subject.pem CA_certificate [CA_certificate ...]"
                << std::endl;
      return 1;
      }

   X509_Certificate subject_cert(args[1]);

   Certificate_Store_In_Memory certs;

   for(const auto certfile : std::vector<std::string>(args.begin()+2, args.end()))
      {
      certs.add_certificate(X509_Certificate(certfile));
      }

   Path_Validation_Restrictions restrictions;

   Path_Validation_Result result =
      x509_path_validate(subject_cert,
                         restrictions,
                         certs);

   if(result.successful_validation())
      std::cout << "Certificate validated" << std::endl;
   else
      std::cout << "Certificate did not validate - " << result.result_string() << std::endl;

   return 0;
   }

REGISTER_APP(cert_verify);

}

#endif // BOTAN_HAS_X509_CERTIFICATES
