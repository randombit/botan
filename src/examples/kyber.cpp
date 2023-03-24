#include <botan/pubkey.h>
#include <botan/kyber.h>
#include <botan/system_rng.h>
#include <array>
#include <iostream>

int main()
   {
   const size_t shared_key_len = 32;
   const std::string kdf = "HKDF(SHA-512)";

   Botan::System_RNG rng;

   std::array<uint8_t, 16> salt;
   rng.randomize(salt);

   Botan::Kyber_PrivateKey priv_key(rng, Botan::KyberMode::Kyber512);
   auto pub_key = priv_key.public_key();

   Botan::PK_KEM_Encryptor enc(*pub_key, kdf);

   Botan::secure_vector<uint8_t> encapsulated_key;
   Botan::secure_vector<uint8_t> enc_shared_key;
   enc.encrypt(encapsulated_key, enc_shared_key, shared_key_len, rng, salt);

   Botan::PK_KEM_Decryptor dec(priv_key, rng, kdf);

   auto dec_shared_key = dec.decrypt(encapsulated_key, shared_key_len, salt);

   if(dec_shared_key != enc_shared_key)
      {
      std::cerr << "Shared keys differ\n";
      return 1;
      }

   return 0;
   }
