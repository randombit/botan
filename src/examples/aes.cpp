#include <botan/block_cipher.h>
#include <botan/hex.h>

#include <iostream>

int main() {
   std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
   std::vector<uint8_t> block = Botan::hex_decode("00112233445566778899AABBCCDDEEFF");
   const auto cipher = Botan::BlockCipher::create_or_throw("AES-256");
   cipher->set_key(key);
   cipher->encrypt(block);
   std::cout << '\n' << cipher->name() << "single block encrypt: " << Botan::hex_encode(block);

   // clear cipher for 2nd encryption with other key
   cipher->clear();
   key = Botan::hex_decode("1337133713371337133713371337133713371337133713371337133713371337");
   cipher->set_key(key);
   cipher->encrypt(block);

   std::cout << '\n' << cipher->name() << "single block encrypt: " << Botan::hex_encode(block);
   return 0;
}
