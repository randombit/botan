#include <botan/auto_rng.h>
#include <botan/mldsa_comp.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>

#include <iostream>
#include <vector>

int main() {
   // Create a random number generator used for key generation.
   Botan::AutoSeeded_RNG rng;

   // create a new public/private key pair for the ML-DSA-44 / ECDSA-P256
   // composite signature scheme.
   const auto param =
      Botan::MLDSA_Composite_Param::from_id_supported_or_throw(Botan::MLDSA_Composite_Param::MLDSA44_ECDSA_P256_SHA256);
   const Botan::MLDSA_Composite_PrivateKey private_key(rng, param);
   const auto public_key = private_key.public_key();

   // create Public Key Signer using the private key.
   Botan::PK_Signer signer(private_key, rng, "");

   // create and sign a message using the Public Key Signer.
   Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04};
   auto sig = signer.sign_message(msg, rng);

   // create Public Key Verifier using the public key
   Botan::PK_Verifier verifier(*public_key, "");

   // verify the signature for the previously generated message.
   if(verifier.verify_message(msg, sig)) {
      std::cout << "Success.\n";
      return 0;
   } else {
      std::cout << "Error.\n";
      return 1;
   }
}
