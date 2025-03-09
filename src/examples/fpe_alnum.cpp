#include <botan/fpe_fe1.h>
#include <botan/hex.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {

constexpr size_t power(size_t b, size_t e) {
   size_t p = 1;

   for(size_t i = 0; i != e; ++i) {
      p *= b;
   }

   return p;
}

/*
* This example FPE encrypts strings of length 10 which
* are in [A-Z0-9], ie radix 36.
*/
constexpr size_t LEN = 10;
constexpr size_t RADIX = 26 + 10;
constexpr size_t POWER = power(RADIX, LEN);

size_t to_radix(char c) {
   if(c >= '0' && c <= '9') {
      return c - '0';
   } else if(c >= 'A' && c <= 'Z') {
      return c - 'A' + 10;
   } else {
      throw std::invalid_argument("String contains unexpected character");
   }
}

// Map from the string to an integer in [0,RADIX**LEN)
Botan::BigInt rank(std::string_view s) {
   if(s.size() != LEN) {
      throw std::invalid_argument("Cannot FPE encrypt string of incorrect length");
   }

   Botan::BigInt z = 0;

   for(size_t i = 0; i != LEN; ++i) {
      z = z * RADIX + to_radix(s[i]);
   }

   return z;
}

char from_radix(size_t c) {
   if(c <= 9) {
      return static_cast<char>(c + '0');
   } else if(c <= 35) {
      return static_cast<char>(c + 'A' - 10);
   } else {
      throw std::invalid_argument("Output contains unexpected character");
   }
}

// Map from an integer in [0,RADIX**LEN) to the string
std::string derank(Botan::BigInt z) {
   std::string s;

   for(size_t i = 0; i != LEN; ++i) {
      const auto zi = z % RADIX;
      s.push_back(from_radix(zi));
      z /= RADIX;
   }

   std::reverse(s.begin(), s.end());

   return s;
}

}  // namespace

int main(int argc, char* argv[]) {
   if(argc <= 3) {
      std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <hex_key> <alnum_input...>\n";
      return 1;
   }

   try {
      const bool encrypt = [=]() {
         const std::string arg1(argv[1]);
         if(arg1 == "encrypt") {
            return true;
         } else if(arg1 == "decrypt") {
            return false;
         } else {
            throw std::invalid_argument("Expected 'encrypt' or 'decrypt' not " + arg1);
         }
      }();

      const auto key = Botan::hex_decode(argv[2]);

      Botan::FPE_FE1 fpe(Botan::BigInt::from_u64(POWER));
      fpe.set_key(key);

      for(size_t i = 3; argv[i] != nullptr; ++i) {
         /*
         * The tweak ensures that even if the same input is encrypted more than
         * once it produces a different output. The same tweak must be used for
         * decryption.  Commonly this is available, eg a database row id. If not
         * available then the tweak can be set to a constant.
         */
         const uint64_t tweak = static_cast<uint64_t>(i - 3);

         auto z = rank(std::string(argv[i]));
         auto enc_z = encrypt ? fpe.encrypt(z, tweak) : fpe.decrypt(z, tweak);
         auto enc_word = derank(enc_z);
         std::cout << enc_word << " ";
      }
      std::cout << "\n";
      return 0;
   } catch(std::exception& e) {
      std::cout << e.what() << "\n";
      return 2;
   }
}
