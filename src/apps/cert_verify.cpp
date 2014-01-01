/*
* Simple example of a certificate validation
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "apps.h"
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <iostream>

using namespace Botan;

int cert_verify(int argc, char* argv[])
   {
   if(argc <= 2)
      {
      std::cout << "Usage: " << argv[0] << " subject.pem [CA certificates...]\n";
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
      std::cout << "Certificate validated\n";
   else
      std::cout << "Certificate did not validate - " << result.result_string() << "\n";

   return 0;
   }
