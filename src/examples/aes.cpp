#include <botan/block_cipher.h>
#include <botan/hex.h>

#include <iostream>

int main() {
   auto key = Botan::hex_decode_locked("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
   auto block = Botan::hex_decode_locked("00112233445566778899AABBCCDDEEFF");
   const auto cipher = Botan::BlockCipher::create_or_throw("AES-256");
   cipher->set_key(key);
   cipher->encrypt(block);
   std::cout << cipher->name() << " single block encrypt: " << Botan::hex_encode(block) << '\n';

   // clear cipher for 2nd encryption with other key
   cipher->clear();
   key = Botan::hex_decode_locked("1337133713371337133713371337133713371337133713371337133713371337");
   cipher->set_key(key);
   cipher->encrypt(block);

   std::cout << cipher->name() << " single block encrypt: " << Botan::hex_encode(block) << '\n';
   return 0;
}
