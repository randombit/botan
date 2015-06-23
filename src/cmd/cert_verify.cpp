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

int cert_verify(int argc, char* argv[])
   {
   using namespace Botan;

   if(argc <= 2)
      {
      std::cout << "Usage: " << argv[0] << " subject.pem [CA certificates...]" << std::endl;
      return 1;
      }

   X509_Certificate subject_cert(argv[1]);

   Certificate_Store_In_Memory certs;

   for(size_t i = 2; argv[i]; ++i)
      certs.add_certificate(X509_Certificate(argv[i]));

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

}

REGISTER_APP(cert_verify);

#endif
