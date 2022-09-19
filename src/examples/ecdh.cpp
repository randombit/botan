#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

#include <iostream>

int main() {
  Botan::AutoSeeded_RNG rng;
  // ec domain and
  Botan::EC_Group domain("secp521r1");
  std::string kdf = "KDF2(SHA-256)";
  // generate ECDH keys
  Botan::ECDH_PrivateKey keyA(rng, domain);
  Botan::ECDH_PrivateKey keyB(rng, domain);
  // Construct key agreements
  Botan::PK_Key_Agreement ecdhA(keyA, rng, kdf);
  Botan::PK_Key_Agreement ecdhB(keyB, rng, kdf);
  // Agree on shared secret and derive symmetric key of 256 bit length
  Botan::secure_vector<uint8_t> sA = ecdhA.derive_key(32, keyB.public_value()).bits_of();
  Botan::secure_vector<uint8_t> sB = ecdhB.derive_key(32, keyA.public_value()).bits_of();

  if (sA != sB)
    return 1;

  std::cout << "agreed key: " << std::endl << Botan::hex_encode(sA);
  return 0;
}
