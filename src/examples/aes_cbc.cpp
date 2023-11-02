#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/rng.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;

   const std::string plaintext(
      "Your great-grandfather gave this watch to your granddad for good "
      "luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
   const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

   const auto enc = Botan::Cipher_Mode::create_or_throw("AES-128/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
   enc->set_key(key);

   // generate fresh nonce (IV)
   Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

   // Copy input data to a buffer that will be encrypted
   Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());

   enc->start(iv);
   enc->finish(pt);

   std::cout << enc->name() << " with iv " << Botan::hex_encode(iv) << " " << Botan::hex_encode(pt) << '\n';
   return 0;
}
