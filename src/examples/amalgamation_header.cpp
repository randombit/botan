#include <iostream>
#if __has_include(<botan/botan_all.h>)
   #include <botan/botan_all.h>

int main() {
   std::cout << "Build with amalgamation.\n";
   std::cout << "That's " << Botan::hex_encode(std::vector<uint8_t>{0xC0, 0x01}) << "\n";
   return 0;
}
#else
int main() {
   std::cout << "Build without amalgamation.\n";
   return 0;
}
#endif
