#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;
   // Generate ECDSA keypair
   Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp521r1"));

   const std::string message("This is a tasty burger!");

   // sign data
   Botan::PK_Signer signer(key, rng, "SHA-256");
   signer.update(message);
   std::vector<uint8_t> signature = signer.signature(rng);
   std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);

   // now verify the signature
   Botan::PK_Verifier verifier(key, "SHA-256");
   verifier.update(message);
   std::cout << std::endl << "is " << (verifier.check_signature(signature) ? "valid" : "invalid");
   return 0;
}
