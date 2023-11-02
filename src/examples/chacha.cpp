#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/stream_cipher.h>

#include <iostream>

int main() {
   std::string plaintext("This is a tasty burger!");
   std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
   const std::vector<uint8_t> key =
      Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
   const auto cipher = Botan::StreamCipher::create_or_throw("ChaCha(20)");

   // generate fresh nonce (IV)
   Botan::AutoSeeded_RNG rng;
   const auto iv = rng.random_vec<std::vector<uint8_t>>(8);

   // set key and IV
   cipher->set_key(key);
   cipher->set_iv(iv);
   cipher->encipher(pt);

   std::cout << cipher->name() << " with iv " << Botan::hex_encode(iv) << ": " << Botan::hex_encode(pt) << '\n';
   return 0;
}
