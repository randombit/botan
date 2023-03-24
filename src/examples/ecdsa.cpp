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

  std::string text("This is a tasty burger!");
  std::vector<uint8_t> data(text.data(), text.data() + text.length());
  // sign data
  Botan::PK_Signer signer(key, rng, "SHA-256");
  signer.update(data);
  std::vector<uint8_t> signature = signer.signature(rng);
  std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);
  // verify signature
  Botan::PK_Verifier verifier(key, "SHA-256");
  verifier.update(data);
  std::cout << std::endl << "is " << (verifier.check_signature(signature) ? "valid" : "invalid");
  return 0;
}
