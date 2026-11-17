#include <botan/fpe_ff1.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
   const auto key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

   // The tweak is not secret; it could be for example a database row identifier
   const std::vector<uint8_t> tweak = {1, 2, 3, 4};

   // Encrypt strings of decimal digits
   Botan::FPE_FF1 ff1(10);
   ff1.set_key(key);

   const std::string input = "0123456789";

   // Each numeral must be in the range [0,radix)
   std::vector<uint16_t> numerals;
   for(const char c : input) {
      numerals.push_back(static_cast<uint16_t>(c - '0'));
   }

   ff1.encrypt(numerals, tweak);

   std::string output;
   for(const uint16_t n : numerals) {
      output.push_back(static_cast<char>('0' + n));
   }

   std::cout << input << " encrypts to " << output << "\n";

   ff1.decrypt(numerals, tweak);

   return 0;
}
