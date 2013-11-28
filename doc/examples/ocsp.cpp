#include <botan/botan.h>
#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <botan/ocsp.h>

#include <iostream>

using namespace Botan;

int main(int argc, char* argv[])
   {
   X509_Certificate subject(argv[1]);
   X509_Certificate issuer(argv[2]);

   Certificate_Store_In_Memory cas;
   cas.add_certificate(issuer);
   OCSP::Response resp = OCSP::online_check(issuer, subject, cas);

   if(resp.affirmative_response_for(issuer, subject))
      std::cout << "OCSP check OK\n";
   else
      std::cout << "OCSP check failed\n";
   }
