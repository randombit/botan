/*
* (C) 2009-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
using namespace Botan;

#include <iostream>
#include <memory>

int main()
   {
   Botan::LibraryInitializer init;

   try
      {
      AutoSeeded_RNG rng;

      // Alice and Bob agree on a DH domain to use
      DL_Group shared_domain("modp/ietf/1024");

      // Alice creates a DH key and sends (the public part) to Bob
      DH_PrivateKey private_a(rng, shared_domain);

      // Alice sends to Bob her public key:
      MemoryVector<byte> public_a = private_a.public_value();

      // Bob creates a key with a matching group
      DH_PrivateKey private_b(rng, shared_domain);

      // Bob sends his public key to Alice
      MemoryVector<byte> public_b = private_b.public_value();

      PK_Key_Agreement ka1(private_a, get_kdf("KDF2(SHA-1)"));
      PK_Key_Agreement ka2(private_b, get_kdf("KDF2(SHA-1)"));

      /*
      * Preferably, include some salt or parameter that binds this key
      * generation to the current session (for instance a session
      * identifier, if guaranteed unique, would be a good choice).  Or
      * anything else that both sides can agree on that will never
      * repeat.
      */
      const std::string ka_salt = "alice and bob agree on a key";

      SymmetricKey alice_key = ka1.derive_key(32, public_b, ka_salt);
      SymmetricKey bob_key = ka2.derive_key(32, public_a, ka_salt);

      if(alice_key == bob_key)
         {
         std::cout << "The two keys matched, everything worked\n";
         std::cout << "The shared key was: " << alice_key.as_string() << "\n";
         }
      else
         {
         std::cout << "The two keys didn't match! Hmmm...\n";
         std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
         std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
         }

      // Now use the shared key for encryption or MACing or whatever
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
