#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include <array>
#include <iostream>

int main() {
   // You can change this to "PBKDF2(SHA-512)" or "Scrypt" or "Argon2id" or ...
   const std::string pbkdf_algo = "Argon2i";
   auto pbkdf_runtime = std::chrono::milliseconds(300);
   const size_t output_hash = 32;
   const size_t max_pbkdf_mb = 128;

   auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf_algo);

   auto pwdhash = pwd_fam->tune(output_hash, pbkdf_runtime, max_pbkdf_mb);

   std::cout << "Using params " << pwdhash->to_string() << '\n';

   std::array<uint8_t, 32> salt;
   Botan::system_rng().randomize(salt);

   const std::string password = "tell no one";

   std::array<uint8_t, output_hash> key;
   pwdhash->hash(key, password, salt);

   std::cout << Botan::hex_encode(key) << '\n';

   return 0;
}
