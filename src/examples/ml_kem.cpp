#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>

#include <iostream>

int main() {
   Botan::System_RNG rng;

   // To use a salt with ML-KEM, a Key Derivation Function must be specified.
   const auto kem_options = Botan::PK_KEM_Options().with_kdf("HKDF(SHA-512)");
   const auto salt = rng.random_array<16>();
   const size_t shared_key_len = 32;

   const Botan::ML_KEM_PrivateKey priv_key(rng, Botan::ML_KEM_Mode::ML_KEM_768);
   auto pub_key = priv_key.public_key();

   Botan::PK_KEM_Encryptor enc(*pub_key, kem_options);

   const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

   Botan::PK_KEM_Decryptor dec(priv_key, rng, kem_options);

   auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);

   if(dec_shared_key != kem_result.shared_key()) {
      std::cerr << "Shared keys differ\n";
      return 1;
   }

   return 0;
}
