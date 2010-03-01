/*
* Simple example of a certificate validation
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/x509cert.h>
#include <botan/x509stor.h>

#include <stdio.h>

using namespace Botan;

int main()
   {
   LibraryInitializer init;

   X509_Certificate ca_cert("ca_cert.pem");
   X509_Certificate subject_cert("http_cert.pem");

   X509_Store cert_store;

   cert_store.add_cert(ca_cert, /*trusted=*/true);

   X509_Code code = cert_store.validate_cert(subject_cert);

   if(code == VERIFIED)
      printf("Cert validated\n");
   else
      printf("Cert did not validate, code = %d\n", code);

   return 0;
   }
