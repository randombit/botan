#include <botan/fpe.h>
#include <botan/init.h>

using namespace Botan;

#include <iostream>

int main()
   {
   LibraryInitializer init;

   BigInt n = 100000000;
   BigInt x = 49604394;

   SymmetricKey key("AAAAAAAAAAAAAAAA");
   MemoryVector<byte> tweak(4);

   BigInt c = fpe_encrypt(n, x, key, tweak);
   BigInt p = fpe_decrypt(n, c, key, tweak);

   std::cout << c << ' ' << p << ' ' << x << '\n';
   }
