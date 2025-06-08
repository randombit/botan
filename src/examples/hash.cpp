#include <botan/hash.h>
#include <botan/hex.h>

#include <iostream>

int main() {
   const auto hash1 = Botan::HashFunction::create_or_throw("SHA-256");
   const auto hash2 = Botan::HashFunction::create_or_throw("SHA-384");
   const auto hash3 = Botan::HashFunction::create_or_throw("SHA-3");
   std::vector<uint8_t> buf(2048);

   while(std::cin.good()) {
      // read STDIN to buffer
      std::cin.read(reinterpret_cast<char*>(buf.data()), buf.size());
      size_t readcount = std::cin.gcount();
      // update hash computations with read data
      hash1->update(std::span{buf}.first(readcount));
      hash2->update(std::span{buf}.first(readcount));
      hash3->update(std::span{buf}.first(readcount));
   }
   std::cout << "SHA-256: " << Botan::hex_encode(hash1->final()) << '\n';
   std::cout << "SHA-384: " << Botan::hex_encode(hash2->final()) << '\n';
   std::cout << "SHA-3: " << Botan::hex_encode(hash3->final()) << '\n';
   return 0;
}
