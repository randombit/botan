/*
  Implement the functionality of a simple CA: read in a CA certificate,
  the associated private key, and a PKCS #10 certificate request. Sign the
  request and print out the new certificate.

  File names are hardcoded for simplicity.
    cacert.pem:    The CA's certificate (perhaps created by self_sig)
    caprivate.pem: The CA's private key
    req.pem:       The user's PKCS #10 certificate request

  Written by Jack Lloyd, May 19, 2003

  This file is in the public domain.
*/

#include <botan/botan.h>
#include <botan/x509_ca.h>
using namespace Botan;

#include <iostream>

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " passphrase" << std::endl;
      return 1;
      }

   try {
      LibraryInitializer init;

      // set up our CA
      X509_Certificate ca_cert("cacert.pem");
      std::auto_ptr<PKCS8_PrivateKey> privkey(
         PKCS8::load_key("caprivate.pem", argv[1])
         );
      X509_CA ca(ca_cert, *privkey);

      // got a request
      PKCS10_Request req("req.pem");

      // presumably attempt to verify the req for sanity/accuracy here, but
      // as Verisign, etc have shown, that's not a must. :)

      // now sign it
      X509_Certificate new_cert = ca.sign_request(req);

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
