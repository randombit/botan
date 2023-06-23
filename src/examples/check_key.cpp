#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <botan/rng.h>
#include <botan/x509cert.h>
#include <iostream>

int main() {
   Botan::X509_Certificate cert("cert.pem");
   Botan::AutoSeeded_RNG rng;
   auto key = cert.subject_public_key();
   if(!key->check_key(rng, false)) {
      std::cerr << "Loaded key is invalid";
      return 1;
   }

   return 0;
}
