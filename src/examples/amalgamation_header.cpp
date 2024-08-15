#include <iostream>
#if __has_include(<botan/botan_all.h>)
   #include <botan/botan_all.h>
#else
   // if the amalgamation header isn't available, you have to IWYU.
   #include <botan/hex.h>
#endif

int main() {
   std::cout << "With an amalgamation build you can include everything using the botan_all header.\n";
   std::cout << "That's " << Botan::hex_encode(std::vector<uint8_t>{0xC0, 0x01}) << "\n";
   return 0;
}
