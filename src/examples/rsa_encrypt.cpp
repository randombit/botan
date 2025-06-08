#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>

#include <iostream>

int main(int argc, char* argv[]) {
   if(argc != 2) {
      return 1;
   }
   std::string_view plaintext(
      "Your great-grandfather gave this watch to your granddad for good luck. "
      "Unfortunately, Dane's luck wasn't as good as his old man's.");
   const Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
   Botan::AutoSeeded_RNG rng;

   // load keypair
   Botan::DataSource_Stream in(argv[1]);
   auto kp = Botan::PKCS8::load_key(in);

   // encrypt with pk
   Botan::PK_Encryptor_EME enc(*kp, rng, "OAEP(SHA-256)");
   const auto ct = enc.encrypt(pt, rng);

   // decrypt with sk
   Botan::PK_Decryptor_EME dec(*kp, rng, "OAEP(SHA-256)");
   const auto pt2 = dec.decrypt(ct);

   std::cout << "\nenc: " << Botan::hex_encode(ct) << "\ndec: " << Botan::hex_encode(pt2);

   return 0;
}
