#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>

#include <iostream>

int main() {
   const size_t shared_key_len = 32;
   const std::string_view kdf = "HKDF(SHA-512)";

   Botan::System_RNG rng;

   const auto salt = rng.random_array<16>();

   Botan::ML_KEM_PrivateKey priv_key(rng, Botan::ML_KEM_Mode::ML_KEM_768);
   auto pub_key = priv_key.public_key();

   Botan::PK_KEM_Encryptor enc(*pub_key, kdf);

   const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

   Botan::PK_KEM_Decryptor dec(priv_key, rng, kdf);

   auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);

   if(dec_shared_key != kem_result.shared_key()) {
      std::cerr << "Shared keys differ\n";
      return 1;
   }

   return 0;
}
