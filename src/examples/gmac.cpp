#include <botan/hex.h>
#include <botan/mac.h>

#include <iostream>

int main() {
   const std::vector<uint8_t> key =
      Botan::hex_decode("1337133713371337133713371337133713371337133713371337133713371337");
   const std::vector<uint8_t> nonce = Botan::hex_decode("FFFFFFFFFFFFFFFFFFFFFFFF");
   const std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
   const auto mac = Botan::MessageAuthenticationCode::create_or_throw("GMAC(AES-256)");
   if(!mac) {
      return 1;
   }
   mac->set_key(key);
   mac->start(nonce);
   mac->update(data);
   Botan::secure_vector<uint8_t> tag = mac->final();
   std::cout << mac->name() << ": " << Botan::hex_encode(tag) << '\n';

   // Verify created MAC
   mac->start(nonce);
   mac->update(data);
   std::cout << "Verification: " << (mac->verify_mac(tag) ? "success" : "failure");
   return 0;
}
