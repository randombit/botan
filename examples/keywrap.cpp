/*
* NIST keywrap example
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/rfc3394.h>
#include <botan/hex.h>
#include <iostream>

int main()
   {
   using namespace Botan;

   LibraryInitializer init;

   AutoSeeded_RNG rng;

   // The key to encrypt
   SymmetricKey key(rng, 24);

   // The key encryption key
   SymmetricKey kek(rng, 32);

   std::cout << "Original:  " << key.as_string() << "\n";

   Algorithm_Factory& af = global_state().algorithm_factory();

   SecureVector<byte> enc = rfc3394_keywrap(key.bits_of(), kek, af);

   std::cout << "Encrypted: " << hex_encode(enc) << "\n";

   SecureVector<byte> dec = rfc3394_keyunwrap(enc, kek, af);

   std::cout << "Decrypted: " << hex_encode(dec) << "\n";
   }
