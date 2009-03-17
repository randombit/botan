#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/look_pk.h>

#include <memory>
#include <iostream>

using namespace Botan;

int main()
   {
   Botan::LibraryInitializer init;

   try
      {
      AutoSeeded_RNG rng;

      EC_Domain_Params params = get_EC_Dom_Pars_by_oid("1.3.132.0.8");

      ECDSA_PrivateKey ecdsa(rng, params);

      ECDSA_PublicKey ecdsa_pub = ecdsa;

      /*
      std::cout << params.get_curve().get_p() << "\n";
      std::cout << params.get_order() << "\n";
      std::cout << X509::PEM_encode(ecdsa);
      std::cout << PKCS8::PEM_encode(ecdsa);
      */

      std::auto_ptr<PK_Signer> signer(get_pk_signer(ecdsa, "EMSA1(SHA-256)"));

      const char* message = "Hello World";

      signer->update((const byte*)message, strlen(message));

      SecureVector<byte> sig = signer->signature(rng);

      std::cout << sig.size() << "\n";

      std::auto_ptr<PK_Verifier> verifier(
         get_pk_verifier(ecdsa_pub, "EMSA1(SHA-256)"));

      verifier->update((const byte*)message, strlen(message));

      bool ok = verifier->check_signature(sig);
      if(ok)
         std::cout << "Signature valid\n";
      else
         std::cout << "Bad signature\n";
      }
   catch(std::exception& e)
      {
      std::cout << e.what() << "\n";
      }
   }
