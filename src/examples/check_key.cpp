#include <botan/x509cert.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/pk_keys.h>

int main()
   {
   Botan::X509_Certificate cert("cert.pem");
   std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
   std::unique_ptr<Botan::Public_Key> key(cert.subject_public_key());
   if(!key->check_key(*rng.get(), false))
      {
      throw std::invalid_argument("Loaded key is invalid");
      }
   }
