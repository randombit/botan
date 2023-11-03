#include <botan/p11.h>
#include <botan/p11_types.h>

#include <iostream>
#include <string>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");

   // Sometimes useful if a newly connected token is not detected by the PKCS#11 module
   module.reload();

   Botan::PKCS11::Info info = module.get_info();

   // print library version
   std::cout << std::to_string(info.libraryVersion.major) << "." << std::to_string(info.libraryVersion.minor) << '\n';

   return 0;
}
