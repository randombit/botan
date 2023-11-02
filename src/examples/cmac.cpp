#include <botan/hex.h>
#include <botan/mac.h>

#include <iostream>

int main() {
   const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
   std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
   const auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
   if(!mac) {
      return 1;
   }
   mac->set_key(key);
   mac->update(data);
   Botan::secure_vector<uint8_t> tag = mac->final();
   // Corrupting data
   data.back()++;
   // Verify with corrupted data
   mac->update(data);
   std::cout << "Verification with malformed data: " << (mac->verify_mac(tag) ? "success" : "failure");
   return 0;
}
