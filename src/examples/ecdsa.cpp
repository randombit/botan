#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;
   // Generate ECDSA keypair
   const auto group = Botan::EC_Group::from_name("secp521r1");
   Botan::ECDSA_PrivateKey key(rng, group);

   const std::string message("This is a tasty burger!");

   // sign data
   Botan::PK_Signer signer(key, rng, Botan::PK_Signature_Options_Builder().with_hash("SHA-256").commit());
   signer.update(message);
   std::vector<uint8_t> signature = signer.signature(rng);
   std::cout << "Signature:\n" << Botan::hex_encode(signature);

   // now verify the signature
   Botan::PK_Verifier verifier(key, Botan::PK_Signature_Options_Builder().with_hash("SHA-256").commit());
   verifier.update(message);
   std::cout << "\nis " << (verifier.check_signature(signature) ? "valid" : "invalid");
   return 0;
}
