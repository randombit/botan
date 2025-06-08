#include <botan/hex.h>
#include <botan/mac.h>

#include <iostream>

int main() {
   const auto key = Botan::hex_decode_locked("1337133713371337133713371337133713371337133713371337133713371337");
   const auto nonce = Botan::hex_decode("FFFFFFFFFFFFFFFFFFFFFFFF");
   const auto data = Botan::hex_decode_locked("6BC1BEE22E409F96E93D7E117393172A");

   const auto mac = Botan::MessageAuthenticationCode::create_or_throw("GMAC(AES-256)");
   mac->set_key(key);
   mac->start(nonce);
   mac->update(data);
   const auto tag = mac->final();
   std::cout << mac->name() << ": " << Botan::hex_encode(tag) << '\n';

   // Verify created MAC
   mac->start(nonce);
   mac->update(data);
   std::cout << "Verification: " << (mac->verify_mac(tag) ? "success" : "failure");
   return 0;
}
