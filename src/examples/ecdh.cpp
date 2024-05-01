#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;

   // ec domain and KDF
   const auto domain = Botan::EC_Group::from_name("secp521r1");
   const std::string kdf = "KDF2(SHA-256)";

   // the two parties generate ECDH keys
   Botan::ECDH_PrivateKey key_a(rng, domain);
   Botan::ECDH_PrivateKey key_b(rng, domain);

   // now they exchange their public values
   const auto key_apub = key_a.public_value();
   const auto key_bpub = key_b.public_value();

   // Construct key agreements and agree on a shared secret
   Botan::PK_Key_Agreement ka_a(key_a, rng, kdf);
   const auto sA = ka_a.derive_key(32, key_bpub).bits_of();

   Botan::PK_Key_Agreement ka_b(key_b, rng, kdf);
   const auto sB = ka_b.derive_key(32, key_apub).bits_of();

   if(sA != sB) {
      return 1;
   }

   std::cout << "agreed key:\n" << Botan::hex_encode(sA);
   return 0;
}
