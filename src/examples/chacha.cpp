#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/stream_cipher.h>

#include <iostream>

int main() {
  std::string plaintext("This is a tasty burger!");
  std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
  const std::vector<uint8_t> key =
      Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
  std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha(20)"));

  // generate fresh nonce (IV)
  Botan::AutoSeeded_RNG rng;
  std::vector<uint8_t> iv(8);
  rng.randomize(iv.data(), iv.size());

  // set key and IV
  cipher->set_key(key);
  cipher->set_iv(iv.data(), iv.size());
  cipher->encipher(pt);

  std::cout << cipher->name() << " with iv " << Botan::hex_encode(iv) << ": "
            << Botan::hex_encode(pt) << "\n";
  return 0;
}
