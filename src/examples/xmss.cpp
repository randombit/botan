#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>
#include <botan/xmss.h>

#include <iostream>

int main() {
   // Create a random number generator used for key generation.
   Botan::AutoSeeded_RNG rng;

   // create a new public/private key pair using SHA2 256 as hash
   // function and a tree height of 10.
   Botan::XMSS_PrivateKey private_key(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_10_256, rng);
   const Botan::XMSS_PublicKey& public_key(private_key);

   // create Public Key Signer using the private key.
   auto signer = private_key.signer().with_rng(rng).create();

   // create and sign a message using the Public Key Signer.
   Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04};
   auto sig = signer.sign_message(msg, rng);

   // create Public Key Verifier using the public key
   auto verifier = public_key.signature_verifier().create();

   // verify the signature for the previously generated message.
   if(verifier.verify_message(msg, sig)) {
      std::cout << "Success.\n";
      return 0;
   } else {
      std::cout << "Error.\n";
      return 1;
   }
}
