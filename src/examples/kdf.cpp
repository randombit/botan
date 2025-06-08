#include <botan/hex.h>
#include <botan/kdf.h>
#include <iostream>

int main() {
   // Replicate a test from RFC 5869
   // https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
   const Botan::secure_vector<uint8_t> input_secret(22, 0x0b);
   const std::vector<uint8_t> salt = Botan::hex_decode("000102030405060708090a0b0c");
   const std::vector<uint8_t> label = Botan::hex_decode("f0f1f2f3f4f5f6f7f8f9");
   const size_t derived_key_len = 42;

   auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
   auto derived_key = kdf->derive_key(derived_key_len, input_secret, salt, label);

   // OKM = 0x3cb25f25faacd57a90434f64d0362f2a...
   std::cout << Botan::hex_encode(derived_key) << '\n';
}
