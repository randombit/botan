#include <botan/botan.h>
#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>

#include <iostream>

using namespace Botan;

int main(int argc, char* argv[])
   {
   if(argc != 2)
      std::cout << "Usage: ocsp subject.pem issuer.pem";

   X509_Certificate subject(argv[1]);
   X509_Certificate issuer(argv[2]);

   Certificate_Store_In_Memory cas;
   cas.add_certificate(issuer);
   OCSP::Response resp = OCSP::online_check(issuer, subject, &cas);

   auto status = resp.status_for(issuer, subject);

   if(status == Certificate_Status_Code::VERIFIED)
      std::cout << "OCSP check OK\n";
   else
      std::cout << "OCSP check failed " << Path_Validation_Result::status_string(status) << "\n";
   }
